// Package contracttest is the shared contract-test harness. Given an OpenAPI document it
// calls every operation, using the examples in the spec as inputs, against any base URL
// (the real service or its double/) and checks the responses against the contract.
//
// Per operation it verifies: the response status is the operation's lowest declared 2xx;
// the media type is declared; the body validates against the response schema; for
// operations taking Idempotency-Key, a replay returns the same status and body; and, when
// ExpectExamples is set (doubles), the body equals the spec's response example. It also
// checks that an unknown route yields a 404 application/problem+json.
//
// Requests are example-driven and stateless: the target must be seeded so the spec's
// examples resolve (a double serves them; a real service is seeded by the caller).
package contracttest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// Options configures a contract run.
type Options struct {
	// SpecPath is the OpenAPI document (external $refs are resolved relative to it).
	SpecPath string
	// BaseURL of the system under test, without trailing slash, e.g. an httptest server URL.
	BaseURL string
	// Client defaults to a client with a 10s timeout.
	Client *http.Client
	// Header is added to every request (for example Authorization from authtest).
	Header http.Header
	// Skip maps operationId to the reason it is skipped. A reason is mandatory.
	Skip map[string]string
	// ExpectExamples additionally requires the body to equal the spec's response example.
	// Set it for doubles, which must serve the spec's examples.
	ExpectExamples bool
	// SeedWorld, when set, is called before each operation with the operation's example world
	// (its x-example-world extension, default DefaultWorld) so a stateful target can be put into
	// the state the operation's examples assume. A world is a named fixture declared in the
	// spec's info.x-example-worlds; see docs/conventions.md. It is not called again for the
	// idempotent replay. An error fails that operation.
	SeedWorld func(ctx context.Context, world string) error
}

// DefaultWorld is the example world of operations that declare no x-example-world.
const DefaultWorld = "base"

// OperationReport is the outcome for one operation (or the pseudo-operation "unknown-route").
type OperationReport struct {
	OperationID string
	Skipped     string   // reason, if skipped
	Failures    []string // empty on success
}

// Run executes Verify and reports each operation as a subtest.
func Run(t *testing.T, o Options) {
	t.Helper()
	reports, err := Verify(context.Background(), o)
	if err != nil {
		t.Fatalf("contract setup: %v", err)
	}
	for _, r := range reports {
		t.Run(r.OperationID, func(t *testing.T) {
			if r.Skipped != "" {
				t.Skip(r.Skipped)
			}
			for _, f := range r.Failures {
				t.Error(f)
			}
		})
	}
}

// Verify runs the contract checks and returns one report per operation, sorted by operationId.
func Verify(ctx context.Context, o Options) ([]OperationReport, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	doc, err := loader.LoadFromFile(o.SpecPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("spec invalid: %w", err)
	}
	doc.Servers = nil // match any host; the base URL is supplied by Options
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("router: %w", err)
	}
	h := &harness{o: o, router: router}
	if h.o.Client == nil {
		h.o.Client = &http.Client{Timeout: 10 * time.Second}
	}

	var reports []OperationReport
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.OperationID == "" {
				return nil, fmt.Errorf("%s %s has no operationId", method, path)
			}
			r := OperationReport{OperationID: op.OperationID}
			if reason, ok := o.Skip[op.OperationID]; ok {
				if reason == "" {
					return nil, fmt.Errorf("skip of %s needs a reason", op.OperationID)
				}
				r.Skipped = reason
			} else {
				r.Failures = h.checkOperation(ctx, path, method, item, op)
			}
			reports = append(reports, r)
		}
	}
	reports = append(reports, OperationReport{OperationID: "unknown-route", Failures: h.checkUnknownRoute(ctx)})
	sort.Slice(reports, func(i, j int) bool { return reports[i].OperationID < reports[j].OperationID })
	return reports, nil
}

type harness struct {
	o      Options
	router routers.Router
}

func (h *harness) checkOperation(ctx context.Context, path, method string, item *openapi3.PathItem, op *openapi3.Operation) (fails []string) {
	fail := func(format string, a ...any) { fails = append(fails, fmt.Sprintf(format, a...)) }

	expStatus, expResp := lowest2xx(op)
	if expStatus == 0 {
		return []string{"operation declares no 2xx response"}
	}
	if h.o.SeedWorld != nil {
		if err := h.o.SeedWorld(ctx, WorldOf(op)); err != nil {
			return []string{fmt.Sprintf("seeding example world %q: %v", WorldOf(op), err)}
		}
	}
	req, bodyBytes, err := h.buildRequest(ctx, path, method, item, op)
	if err != nil {
		return []string{"cannot build request from spec examples: " + err.Error()}
	}
	status, ctype, body, err := h.do(req, bodyBytes)
	if err != nil {
		return []string{"request failed: " + err.Error()}
	}
	if status != expStatus {
		fail("status %d, want %d (body: %s)", status, expStatus, truncate(body))
		return fails
	}
	fails = append(fails, h.checkResponse(req, bodyBytes, status, ctype, body)...)

	if h.o.ExpectExamples {
		if want, ok := exampleFor(expResp); ok {
			if !jsonEqual(want, body) {
				fail("body does not equal the spec example for %d", status)
			}
		}
	}
	if hasParam(op, "Idempotency-Key") {
		req2, _, err := h.buildRequest(ctx, path, method, item, op)
		if err == nil {
			s2, _, b2, err := h.do(req2, bodyBytes)
			switch {
			case err != nil:
				fail("replay failed: %v", err)
			case s2 == 409 && problemCode(b2) == "idempotency.replay_secret":
				// The original response carried a one-time secret (token, code, half, pack). It is never
				// stored, so the replay is refused and the secret is not returned again (SR-H4).
				if strings.Contains(string(b2), "token") && !strings.Contains(string(b2), "replay_secret") {
					fail("replay_secret answer carries a secret")
				}
			case rerunOps[op.OperationID]:
				// Token-issuing operations are not recorded: the replay runs again and meets the credential
				// checks (reuse detection, spent code), so any answer except a server error or an
				// idempotency mismatch is acceptable.
				if s2 >= 500 || problemCode(b2) == "idempotency.mismatch" {
					fail("replay of %s returned %d %s", op.OperationID, s2, problemCode(b2))
				}
			case s2 != status:
				fail("idempotent replay returned status %d, want %d", s2, status)
			case !jsonEqual2(stripOneTime(expResp, body), stripOneTime(expResp, b2)):
				fail("idempotent replay returned a different body")
			}
		}
	}
	return fails
}

func (h *harness) checkResponse(req *http.Request, reqBody []byte, status int, ctype string, body []byte) (fails []string) {
	route, pathParams, err := h.router.FindRoute(req)
	if err != nil {
		return []string{"route not found in spec: " + err.Error()}
	}
	in := &openapi3filter.RequestValidationInput{Request: req, PathParams: pathParams, Route: route}
	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in,
		Status:                 status,
		Header:                 http.Header{"Content-Type": []string{ctype}},
		Options:                &openapi3filter.Options{IncludeResponseStatus: true},
	}
	out.SetBodyBytes(body)
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		fails = append(fails, "response violates contract: "+err.Error())
	}
	return fails
}

func (h *harness) checkUnknownRoute(ctx context.Context) []string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.o.BaseURL+"/v1/__contract-no-such-route", nil)
	h.addHeaders(req)
	status, ctype, body, err := h.do(req, nil)
	if err != nil {
		return []string{"request failed: " + err.Error()}
	}
	var fails []string
	if status != http.StatusNotFound && status != http.StatusUnauthorized {
		fails = append(fails, fmt.Sprintf("unknown route status %d, want 404 (or 401 before auth)", status))
	}
	if mt, _, _ := mime.ParseMediaType(ctype); mt != "application/problem+json" {
		fails = append(fails, fmt.Sprintf("unknown route content type %q, want application/problem+json", ctype))
	} else {
		var raw map[string]any
		if json.Unmarshal(body, &raw) != nil || raw["type"] == nil || raw["title"] == nil || raw["status"] == nil {
			fails = append(fails, "unknown route body is not a Problem (type, title, status)")
		}
	}
	return fails
}

func (h *harness) addHeaders(req *http.Request) {
	for k, vs := range h.o.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
}

func (h *harness) do(req *http.Request, body []byte) (int, string, []byte, error) {
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	resp, err := h.o.Client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, resp.Header.Get("Content-Type"), b, err
}

func (h *harness) buildRequest(ctx context.Context, path, method string, item *openapi3.PathItem, op *openapi3.Operation) (*http.Request, []byte, error) {
	params := append(openapi3.Parameters{}, item.Parameters...)
	params = append(params, op.Parameters...)
	u := path
	q := url.Values{}
	hdr := http.Header{}
	for _, pr := range params {
		p := pr.Value
		ex, ok := paramExample(p)
		if !ok {
			if p.Required {
				return nil, nil, fmt.Errorf("required %s parameter %q has no example", p.In, p.Name)
			}
			continue
		}
		s := fmt.Sprint(ex)
		switch p.In {
		case "path":
			u = strings.ReplaceAll(u, "{"+p.Name+"}", url.PathEscape(s))
		case "query":
			q.Set(p.Name, s)
		case "header":
			if strings.EqualFold(p.Name, "Idempotency-Key") {
				// Distinct, deterministic key per operation so one example key never collides
				// across operations on a stateful target.
				s = op.OperationID + ":" + s
			}
			hdr.Set(p.Name, s)
		}
	}
	var body []byte
	if op.RequestBody != nil {
		mt := op.RequestBody.Value.Content.Get("application/json")
		if mt == nil {
			return nil, nil, fmt.Errorf("request body has no application/json media type")
		}
		ex, ok := mediaExample(mt)
		if !ok {
			return nil, nil, fmt.Errorf("request body has no example")
		}
		var err error
		if body, err = json.Marshal(ex); err != nil {
			return nil, nil, err
		}
	}
	full := h.o.BaseURL + u
	if len(q) > 0 {
		full += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, full, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header = hdr
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	h.addHeaders(req)
	return req, body, nil
}

// WorldOf returns the operation's example world: its x-example-world extension or DefaultWorld.
func WorldOf(op *openapi3.Operation) string {
	if w, ok := op.Extensions["x-example-world"].(string); ok && w != "" {
		return w
	}
	return DefaultWorld
}

func lowest2xx(op *openapi3.Operation) (int, *openapi3.Response) {
	best := 0
	var resp *openapi3.Response
	for code, r := range op.Responses.Map() {
		var n int
		if _, err := fmt.Sscanf(code, "%d", &n); err == nil && n >= 200 && n < 300 && (best == 0 || n < best) {
			best, resp = n, r.Value
		}
	}
	return best, resp
}

func paramExample(p *openapi3.Parameter) (any, bool) {
	if p.Example != nil {
		return p.Example, true
	}
	for _, e := range p.Examples {
		if e.Value != nil {
			return e.Value.Value, true
		}
	}
	if p.Schema != nil && p.Schema.Value != nil && p.Schema.Value.Example != nil {
		return p.Schema.Value.Example, true
	}
	return nil, false
}

func mediaExample(mt *openapi3.MediaType) (any, bool) {
	if mt.Example != nil {
		return mt.Example, true
	}
	names := make([]string, 0, len(mt.Examples))
	for n := range mt.Examples {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if e := mt.Examples[n]; e.Value != nil {
			return e.Value.Value, true
		}
	}
	return nil, false
}

func exampleFor(r *openapi3.Response) (any, bool) {
	if r == nil {
		return nil, false
	}
	if mt := r.Content.Get("application/json"); mt != nil {
		return mediaExample(mt)
	}
	return nil, false
}

func hasParam(op *openapi3.Operation, name string) bool {
	for _, p := range op.Parameters {
		if p.Value != nil && strings.EqualFold(p.Value.Name, name) {
			return true
		}
	}
	return false
}

func jsonEqual(want any, got []byte) bool {
	var g any
	if json.Unmarshal(got, &g) != nil {
		return false
	}
	wb, _ := json.Marshal(want)
	var w any
	_ = json.Unmarshal(wb, &w)
	return reflect.DeepEqual(w, g)
}

func jsonEqual2(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	return reflect.DeepEqual(x, y)
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

// stripOneTime removes from a top-level JSON object the response properties marked x-one-time-secret in the spec, and the
// flag named by their withheld_flag. A one-time secret (an invitation code) is shown once and never stored, so a replay
// legitimately omits it; everything else must be identical.
func stripOneTime(resp *openapi3.Response, body []byte) []byte {
	if resp == nil {
		return body
	}
	var drop []string
	for _, mt := range resp.Content {
		if mt.Schema == nil || mt.Schema.Value == nil {
			continue
		}
		for name, ref := range mt.Schema.Value.Properties {
			if ref.Value == nil {
				continue
			}
			ext, ok := ref.Value.Extensions["x-one-time-secret"]
			if !ok {
				continue
			}
			drop = append(drop, name)
			if m, ok := ext.(map[string]any); ok {
				if f, ok := m["withheld_flag"].(string); ok {
					drop = append(drop, f)
				}
			}
		}
	}
	if len(drop) == 0 {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	for _, d := range drop {
		delete(m, d)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// rerunOps are the token-issuing operations whose replay is not answered from a stored response.
var rerunOps = map[string]bool{
	"createSession": true, "refreshSession": true, "createDeviceToken": true, "createDrainToken": true,
	"createVendorSession": true, "renewVendorSession": true,
}

func problemCode(b []byte) string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b, &p)
	return p.Code
}
