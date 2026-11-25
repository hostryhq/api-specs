// Command validate-worlds checks every example in the repository against the shared example worlds in examples/worlds
// (docs/conventions.md, "Example worlds"). One id names one thing: an id that no world declares, an id whose kind does not
// fit the field it sits in (a vendor user as a member), a GSTIN with a wrong check character or that no registration
// owns, a series code outside the registry alphabet or that no series owns, an entity whose declared facts differ from
// the example, a deterministic row id that is not the UUIDv5 of its natural key, a duplicated event id, a continuation
// cursor in a response example, or a conformance-vector count that disagrees with the vector file all fail the build.
// Usage: validate-worlds <repo-root>.
package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type entry struct {
	Name   string            `yaml:"name"`
	ID     string            `yaml:"id"`
	Kind   string            `yaml:"kind"`
	Facts  map[string]string `yaml:"facts"`
	Note   string            `yaml:"note"`
	Derive *struct {
		Entity string            `yaml:"entity"`
		Args   map[string]string `yaml:"args"`
	} `yaml:"derive"`
}

type world struct {
	World     string            `yaml:"world"`
	Prefix    string            `yaml:"id_prefix"`
	Alphabet  string            `yaml:"series_alphabet"`
	Namespace string            `yaml:"uuid_namespace"`
	Constants map[string]any    `yaml:"constants"`
	Entries   []entry           `yaml:"entries"`
	file      string
	full      map[string]string // entry name -> full id
}

var (
	uuidRe   = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	v7Re     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	v5Re     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	gstinRe  = regexp.MustCompile(`\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b`)
	docNumRe = regexp.MustCompile(`\b([A-Z0-9]{2,3})/([0-9]{4})/([0-9]{6})\b`)
	hexSuffx = regexp.MustCompile(`^[0-9a-f]{4}$`)
)

// keyKinds maps a field name to the kinds an id there may have. A field not listed is not checked.
var keyKinds = map[string][]string{
	"tenant_id": {"organisation"}, "organisation_id": {"organisation"}, "counterparty_organisation_id": {"organisation"},
	"counterparty_tenant_id": {"organisation"}, "outlet_id": {"outlet"}, "outlet_ids": {"outlet"}, "brand_id": {"brand"},
	"tax_registration_id": {"registration"}, "registration_id": {"registration"},
	"member_id": {"member"}, "cashier_id": {"member"}, "closing_member_id": {"member"}, "opened_by_member_id": {"member"},
	"device_id": {"device"}, "origin_device_id": {"device"}, "role_id": {"role"}, "link_id": {"link"},
	"series_id": {"series"}, "session_id": {"session"}, "support_session_id": {"support_session"},
	"vendor_user_id": {"vendor_user"}, "recorded_by": {"vendor_user"}, "requested_by": {"vendor_user", "member"},
	"approved_by": {"vendor_user", "member"}, "approval_id": {"approval", "vendor_approval"},
	"item_id": {"item"}, "category_id": {"category"}, "station_id": {"station"}, "printer_id": {"printer"},
	"floor_id": {"floor"}, "reason_code_id": {"reason_code"}, "check_id": {"check"}, "order_line_id": {"order_line"},
	"kot_id": {"kot"}, "seating_id": {"seating"}, "bill_id": {"bill"}, "credit_note_id": {"credit_note"},
	"payment_id": {"payment", "tenancy_payment"}, "business_day_id": {"business_day"}, "shift_id": {"shift"}, "ruleset_id": {"tax_rule_set"},
	"rule_set_id": {"tax_rule_set"}, "subscription_id": {"subscription"}, "charge_id": {"charge"},
	"exception_id": {"exception"}, "import_id": {"menu_import_job"}, "binding_id": {"binding"},
	"challenge_id": {"otp_challenge"}, "assignment_id": {"role_assignment"}, "amendment_id": {"link_amendment"},
	"grant_id": {"link_grant"}, "recovery_id": {"owner_recovery"}, "request_id": {"approval"},
	"invitation_id": {"invitation"}, "pin_reset_authorisation_id": {"pin_reset_authorisation"},
}

type validator struct {
	root    string
	errs    []string
	byID    map[string]*entry
	byName  map[string]string
	gstins  map[string]bool
	series  map[string]bool
	alpha   string
	ns      [16]byte
	events  map[string]string
	vectors int
	consts  map[string]any
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-worlds <repo-root>")
		os.Exit(2)
	}
	v := &validator{root: os.Args[1], byID: map[string]*entry{}, byName: map[string]string{}, gstins: map[string]bool{},
		series: map[string]bool{}, events: map[string]string{}, consts: map[string]any{}}
	n := v.run()
	if len(v.errs) > 0 {
		sort.Strings(v.errs)
		for i, e := range v.errs {
			if i >= 2000 {
				fmt.Fprintf(os.Stderr, "... and %d more\n", len(v.errs)-i)
				break
			}
			fmt.Fprintln(os.Stderr, "FAIL:", e)
		}
		os.Exit(1)
	}
	fmt.Printf("worlds: %d declared ids, %d GSTINs, %d series; every example in %d documents agrees with them\n", len(v.byID), len(v.gstins), len(v.series), n)
}

func (v *validator) fail(f string, a ...any) { v.errs = append(v.errs, fmt.Sprintf(f, a...)) }

func (v *validator) run() int {
	files, _ := filepath.Glob(filepath.Join(v.root, "examples", "worlds", "*.yaml"))
	if len(files) == 0 {
		v.fail("no worlds under examples/worlds")
		return 0
	}
	uuidv5Entities := v.uuidv5Entities()
	var worlds []*world
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			v.fail("%v", err)
			continue
		}
		w := &world{file: filepath.Base(f), full: map[string]string{}}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(w); err != nil {
			v.fail("%s: %v", w.file, err)
			continue
		}
		worlds = append(worlds, w)
		for k, c := range w.Constants {
			v.consts[k] = c
		}
		if w.Alphabet != "" {
			v.alpha = w.Alphabet
		}
		if w.Namespace != "" {
			v.ns = parseUUID(w.Namespace)
		}
		for i := range w.Entries {
			e := &w.Entries[i]
			id := e.ID
			if hexSuffx.MatchString(id) {
				id = w.Prefix + id
			}
			e.ID = id
			w.full[e.Name] = id
			if prev, dup := v.byName[e.Name]; dup {
				v.fail("%s: name %s is declared twice (also %s)", w.file, e.Name, prev)
			}
			v.byName[e.Name] = id
			if other, dup := v.byID[id]; dup {
				v.fail("%s: id %s is declared as both %s and %s", w.file, id, other.Name, e.Name)
			}
			v.byID[id] = e
		}
	}
	if v.alpha == "" {
		v.fail("worlds: series_alphabet is not declared")
	}
	// per-entry rules
	for _, w := range worlds {
		for i := range w.Entries {
			e := &w.Entries[i]
			at := w.file + " " + e.Name
			if e.Kind == "" {
				v.fail("%s: kind is required", at)
			}
			switch {
			case e.Derive != nil:
				if !v5Re.MatchString(e.ID) {
					v.fail("%s: a derived id is a UUIDv5, got %s", at, e.ID)
				}
				v.checkDerive(w, e, at)
			case !v7Re.MatchString(e.ID):
				v.fail("%s: id %s is not a lower-case UUIDv7", at, e.ID)
			}
			if tmpl, ok := uuidv5Entities[e.Kind]; ok && e.Derive == nil {
				v.fail("%s: entity %s has a deterministic id (%s); the entry needs derive", at, e.Kind, tmpl)
			}
			if g := e.Facts["gstin"]; g != "" {
				if !gstinValid(g) {
					v.fail("%s: GSTIN %s has a wrong check character (want %s)", at, g, gstinCheck(g[:14]))
				}
				v.gstins[g] = true
			}
			if e.Kind == "series" {
				c := e.Facts["code"]
				if len(c) != 3 || strings.Trim(c, v.alpha) != "" {
					v.fail("%s: series code %q must be 3 characters of %s", at, c, v.alpha)
				}
				if v.series[c] {
					v.fail("%s: series code %s is declared twice", at, c)
				}
				v.series[c] = true
			}
		}
	}
	// conformance vectors
	if n, ok := v.consts["tax_vector_count"].(int); ok {
		b, err := os.ReadFile(filepath.Join(v.root, "tax", "conformance", "vectors.v1.json"))
		var f struct {
			Cases []any `json:"cases"`
		}
		if err == nil {
			err = json.Unmarshal(b, &f)
		}
		if err != nil {
			v.fail("tax vectors: %v", err)
		} else if len(f.Cases) != n {
			v.fail("constants.tax_vector_count is %d but tax/conformance/vectors.v1.json holds %d cases", n, len(f.Cases))
		}
		v.vectors = n
	}
	// documents
	var docs []string
	for _, pat := range []string{"openapi/*/v1/openapi.yaml", "openapi/*/v1/*.yaml", "events/*/*.yaml", "common/*.yaml", "entities/*/*.yaml", "sync/intents/*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(v.root, pat))
		docs = append(docs, m...)
	}
	sort.Strings(docs)
	seen := map[string]bool{}
	count := 0
	for _, f := range docs {
		if seen[f] {
			continue
		}
		seen[f] = true
		b, err := os.ReadFile(f)
		if err != nil {
			v.fail("%v", err)
			continue
		}
		var doc any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			v.fail("%s: %v", f, err)
			continue
		}
		count++
		rel, _ := filepath.Rel(v.root, f)
		v.walk(doc, rel, nil, "", false)
	}
	return count
}

// uuidv5Entities lists the entity files that declare a deterministic id: entity name -> name template.
func (v *validator) uuidv5Entities() map[string]string {
	out := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(v.root, "entities", "*", "*.yaml"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		var e struct {
			Entity string `yaml:"entity"`
			ID     struct {
				Rule string `yaml:"rule"`
				Name string `yaml:"name"`
			} `yaml:"id"`
		}
		if yaml.Unmarshal(b, &e) == nil && e.ID.Rule == "uuidv5" {
			out[e.Entity] = e.ID.Name
		}
	}
	return out
}

var placeholder = regexp.MustCompile(`\{([a-z_]+)( or "-")?\}`)

func (v *validator) checkDerive(w *world, e *entry, at string) {
	tmpl := v.uuidv5Entities()[e.Derive.Entity]
	if tmpl == "" {
		v.fail("%s: derive.entity %s has no uuidv5 id rule in entities/", at, e.Derive.Entity)
		return
	}
	name := placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		sub := placeholder.FindStringSubmatch(m)
		arg, ok := e.Derive.Args[sub[1]]
		if !ok {
			if sub[2] != "" {
				return "-"
			}
			v.fail("%s: derive.args lacks %s", at, sub[1])
			return ""
		}
		if id, ok := v.byName[arg]; ok {
			return id
		}
		for _, o := range []*world{w} {
			if id, ok := o.full[arg]; ok {
				return id
			}
		}
		return arg
	})
	// The names a derive refers to may sit in another world file; resolve lazily when not found yet.
	if got := uuid5(v.ns, name); got != e.ID {
		v.fail("%s: id is %s but uuidv5(%q) = %s", at, e.ID, name, got)
	}
}

func (v *validator) walk(n any, file string, path []string, key string, inExample bool) {
	switch t := n.(type) {
	case map[string]any:
		if id, ok := t["id"].(string); ok && uuidRe.MatchString(id) {
			v.checkFacts(file, id, t)
		}
		// path parameter style: {name: member_id, example: <uuid>}
		if name, ok := t["name"].(string); ok {
			if ex, ok := t["example"].(string); ok {
				v.checkKey(file, name, ex)
			}
		}
		for k, c := range t {
			ex := inExample || k == "example" || k == "examples"
			if ex && k == "next_cursor" {
				v.fail("%s: %s: a response example carries next_cursor; a base-world list holds every row, so no continuation", file, strings.Join(append(path, k), "."))
			}
			if ex && (k == "vectors_total" || k == "vectors_passed") && v.vectors > 0 {
				if n, ok := c.(int); ok && n != v.vectors {
					v.fail("%s: %s is %d but the shared vectors hold %d cases", file, k, n, v.vectors)
				}
			}
			v.walk(c, file, append(path, k), k, ex)
		}
	case []any:
		for _, c := range t {
			v.walk(c, file, path, key, inExample)
		}
		if strings.HasPrefix(file, "events/") && key == "examples" && len(path) == 1 {
			for _, c := range t {
				if m, ok := c.(map[string]any); ok {
					v.checkEventID(file, m)
				}
			}
		}
	case string:
		v.checkString(file, strings.Join(path, "."), key, t)
	}
}

func (v *validator) checkEventID(file string, m map[string]any) {
	id, _ := m["id"].(string)
	if e, ok := v.byID[id]; !ok || e.Kind != "event" {
		v.fail("%s: event example id %s is not a world id of kind event", file, id)
		return
	}
	if prev, dup := v.events[id]; dup {
		v.fail("%s: event id %s is also the example id of %s", file, id, prev)
	}
	v.events[id] = file
}

func (v *validator) checkString(file, path, key, s string) {
	for _, id := range uuidRe.FindAllString(s, -1) {
		if _, ok := v.byID[id]; !ok {
			v.fail("%s: %s: id %s is in no example world", file, path, id)
		}
	}
	if key != "" {
		v.checkKey(file, key, s)
	}
	for _, g := range gstinRe.FindAllString(s, -1) {
		switch {
		case !gstinValid(g):
			v.fail("%s: %s: GSTIN %s has a wrong check character (want %s)", file, path, g, gstinCheck(g[:14]))
		case !v.gstins[g]:
			v.fail("%s: %s: GSTIN %s belongs to no registration in the worlds", file, path, g)
		}
	}
	for _, m := range docNumRe.FindAllStringSubmatch(s, -1) {
		if !v.series[m[1]] {
			v.fail("%s: %s: document number %s uses series code %s, which no world series has", file, path, m[0], m[1])
		}
	}
	if (key == "series_code") && s != "" && !v.series[s] {
		v.fail("%s: %s: series_code %s is in no world", file, path, s)
	}
	if key == "cursor" || key == "next_cursor" {
		if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			var c struct {
				After string `json:"after"`
			}
			if json.Unmarshal(b, &c) == nil && c.After != "" {
				if _, ok := v.byID[c.After]; !ok {
					v.fail("%s: %s: cursor decodes to after=%q, which is not a full world id", file, path, c.After)
				}
			}
		}
	}
}

func (v *validator) checkKey(file, key, val string) {
	kinds, ok := keyKinds[key]
	if !ok || !uuidRe.MatchString(val) {
		return
	}
	e, known := v.byID[val]
	if !known {
		return // reported as unknown id
	}
	for _, k := range kinds {
		if e.Kind == k {
			return
		}
	}
	v.fail("%s: field %s holds %s (%s, a %s); it must be a %s", file, key, val, e.Name, e.Kind, strings.Join(kinds, " or "))
}

// checkFacts compares a mapping whose id is a world id with the facts the world declares for it.
func (v *validator) checkFacts(file, id string, m map[string]any) {
	e, ok := v.byID[id]
	if !ok || len(e.Facts) == 0 {
		return
	}
	for k, want := range e.Facts {
		if got, ok := m[k]; ok {
			if s := fmt.Sprint(got); s != want {
				v.fail("%s: %s (%s) has %s %q here but the world says %q", file, id, e.Name, k, s, want)
			}
		}
	}
}

const gstCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func gstinCheck(first14 string) string {
	sum := 0
	for i, c := range first14 {
		val := strings.IndexRune(gstCharset, c)
		if val < 0 {
			return "?"
		}
		f := 1
		if i%2 == 1 {
			f = 2
		}
		p := val * f
		sum += p/36 + p%36
	}
	return string(gstCharset[(36-sum%36)%36])
}

func gstinValid(g string) bool { return len(g) == 15 && gstinCheck(g[:14]) == g[14:] }

func parseUUID(s string) (b [16]byte) {
	h := strings.ReplaceAll(s, "-", "")
	for i := 0; i < 16; i++ {
		fmt.Sscanf(h[2*i:2*i+2], "%02x", &b[i])
	}
	return b
}

func uuid5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	s := h.Sum(nil)
	b := s[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
