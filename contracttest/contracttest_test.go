package contracttest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hostryhq/api-specs/contracttest"
	"github.com/hostryhq/api-specs/examples/ping/double"
)

const spec = "../examples/ping/openapi.yaml"

// The example double must pass the harness, serving the spec's examples.
func TestPingDoublePassesContract(t *testing.T) {
	srv := httptest.NewServer(double.New())
	defer srv.Close()
	contracttest.Run(t, contracttest.Options{SpecPath: spec, BaseURL: srv.URL, ExpectExamples: true})
}

// The harness must catch a server that drifts from the contract.
func TestHarnessDetectsViolations(t *testing.T) {
	good := double.New()
	bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/pings/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"not-an-id"}`)) // missing fields, bad id
		case r.Method == http.MethodGet && r.URL.Path == "/v1/pings":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			good.ServeHTTP(w, r)
		}
	})
	srv := httptest.NewServer(bad)
	defer srv.Close()

	reports, err := contracttest.Verify(context.Background(), contracttest.Options{SpecPath: spec, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	failed := map[string]bool{}
	for _, r := range reports {
		failed[r.OperationID] = len(r.Failures) > 0
	}
	for op, want := range map[string]bool{"getPing": true, "listPings": true, "createPing": false, "unknown-route": false} {
		if failed[op] != want {
			t.Errorf("%s: failed=%v, want %v", op, failed[op], want)
		}
	}
}

// SeedWorld is called once per operation with its world (default "base"), and the
// per-operation Idempotency-Key is distinct.
func TestSeedWorldAndDistinctKeys(t *testing.T) {
	good := double.New()
	keys := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if k := r.Header.Get("Idempotency-Key"); k != "" {
			keys[k]++
		}
		good.ServeHTTP(w, r)
	}))
	defer srv.Close()
	var worlds []string
	reports, err := contracttest.Verify(context.Background(), contracttest.Options{
		SpecPath: spec, BaseURL: srv.URL, ExpectExamples: true,
		SeedWorld: func(_ context.Context, w string) error { worlds = append(worlds, w); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reports {
		if len(r.Failures) > 0 {
			t.Errorf("%s: %v", r.OperationID, r.Failures)
		}
	}
	if len(worlds) != 3 {
		t.Fatalf("seeded %d times, want once per operation (3): %v", len(worlds), worlds)
	}
	for _, w := range worlds {
		if w != contracttest.DefaultWorld {
			t.Errorf("world %q, want default", w)
		}
	}
	if len(keys) != 1 || keys["createPing:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"] != 2 {
		t.Errorf("idempotency keys seen: %v", keys)
	}
}
