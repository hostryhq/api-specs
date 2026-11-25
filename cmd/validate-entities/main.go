// Command validate-entities checks the synced entity schemas under entities/ (ADR-0002 S6, S4 pii rule;
// ADR-0014 R1, R3 ownership): every entity has exactly one owner, a stream, a policy and an id rule;
// every field has a type, a description and a conflict policy that agrees with the entity policy;
// money, tax and numbering fields are never pii; references resolve; the file name is the entity name.
// Usage: validate-entities <entities-dir>.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type field struct {
	Type        string   `yaml:"type"`
	Required    *bool    `yaml:"required"`
	Policy      string   `yaml:"policy"`
	Group       string   `yaml:"group"`
	Description string   `yaml:"description"`
	Values      []string `yaml:"values"`
	Order       []string `yaml:"order"`
	Ref         string   `yaml:"ref"`
	PII         bool     `yaml:"pii"`
	DocNumber   bool     `yaml:"doc_number"`
	Max         *int     `yaml:"max_length"`
}

type entity struct {
	Entity      string `yaml:"entity"`
	EntityV     int    `yaml:"entity_v"`
	Owner       string `yaml:"owner"`
	Stream      string `yaml:"stream"`
	Policy      string `yaml:"policy"`
	Tombstone   bool   `yaml:"tombstone"`
	Guarded     bool   `yaml:"guarded"`
	CloudOrigin bool   `yaml:"cloud_origin_only"`
	ID          struct {
		Rule string `yaml:"rule"`
		Name string `yaml:"name"`
	} `yaml:"id"`
	Description string `yaml:"description"`
	Fields      map[string]field
	Intents     []string `yaml:"written_by_intents"`
}

var (
	owners   = map[string]bool{"catalog": true, "orders": true, "billing": true}
	streams  = map[string]bool{"outlet": true, "brand": true, "tenant": true}
	policies = map[string]bool{"append": true, "lww": true, "rank": true, "mixed": true}
	fpol     = map[string]bool{"immutable": true, "lww": true, "lww_review": true, "delta": true, "rank": true}
	types    = map[string]bool{"id": true, "string": true, "int": true, "bool": true, "enum": true, "paise": true, "qty_milli": true, "bp": true, "date": true, "ts": true}
	snake    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	moneyish = regexp.MustCompile(`(_paise|_bp|number|gstin|tax_class|hsn_sac|sac|series_code|rule_set)`)
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-entities <entities-dir>")
		os.Exit(2)
	}
	errs, n := run(os.Args[1])
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "FAIL:", e)
		}
		os.Exit(1)
	}
	fmt.Printf("entities: %d entity schemas are consistent (one owner each, policies, references, pii)\n", n)
}

func run(dir string) (errs []string, count int) {
	fail := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	files, _ := filepath.Glob(filepath.Join(dir, "*", "*.yaml"))
	sort.Strings(files)
	ents := map[string]entity{}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			fail("%s", err)
			continue
		}
		var e entity
		if err := yaml.Unmarshal(b, &e); err != nil {
			fail("%s: %v", p, err)
			continue
		}
		if filepath.Base(p) != e.Entity+".yaml" {
			fail("%s: file name must be <entity>.yaml (entity is %q)", p, e.Entity)
		}
		if _, dup := ents[e.Entity]; dup {
			fail("%s: entity %s defined twice (every entity has exactly one owner and one file)", p, e.Entity)
		}
		ents[e.Entity] = e
	}
	for _, name := range sortedKeys(ents) {
		e := ents[name]
		at := "entity " + name
		if !snake.MatchString(name) || e.EntityV < 1 || e.Description == "" {
			fail("%s: needs a snake_case name, entity_v >= 1 and a description", at)
		}
		if !owners[e.Owner] {
			fail("%s: owner %q is not catalog, orders or billing", at, e.Owner)
		}
		if !streams[e.Stream] {
			fail("%s: stream %q is not outlet, brand or tenant", at, e.Stream)
		}
		if !policies[e.Policy] {
			fail("%s: policy %q is not append, lww, rank or mixed", at, e.Policy)
		}
		if e.CloudOrigin && e.Stream == "outlet" && !strings.HasPrefix(name, "business_day_revision") {
			// cloud-origin rows are allowed on any stream; revisions are the outlet-stream case
			fail("%s: cloud_origin_only on an outlet-stream entity needs a stated reason (only business_day_revision)", at)
		}
		switch e.ID.Rule {
		case "client_uuidv7":
		case "uuidv5":
			if e.ID.Name == "" {
				fail("%s: uuidv5 id rule needs a name template", at)
			}
		default:
			fail("%s: id rule %q is not client_uuidv7 or uuidv5", at, e.ID.Rule)
		}
		if len(e.Fields) == 0 {
			fail("%s: no fields", at)
		}
		hasRank := false
		for _, fn := range sortedFieldKeys(e.Fields) {
			f := e.Fields[fn]
			fa := at + "." + fn
			if !snake.MatchString(fn) {
				fail("%s: field name must be snake_case", fa)
			}
			if !types[f.Type] {
				fail("%s: unknown type %q", fa, f.Type)
			}
			if f.Description == "" {
				fail("%s: no description", fa)
			}
			if f.Required == nil {
				fail("%s: required must be stated", fa)
			}
			if f.Policy != "" && !fpol[f.Policy] {
				fail("%s: unknown field policy %q", fa, f.Policy)
			}
			p := f.Policy
			if p == "" {
				switch e.Policy {
				case "append":
					p = "immutable"
				case "lww":
					fail("%s: an lww entity states a policy on every field", fa)
				default:
					fail("%s: a %s entity states a policy on every field", fa, e.Policy)
				}
			}
			switch e.Policy {
			case "append":
				if p != "immutable" {
					fail("%s: append entity with field policy %s", fa, p)
				}
			case "lww":
				if p != "lww" && p != "lww_review" && p != "immutable" {
					fail("%s: lww entity with field policy %s", fa, p)
				}
			case "rank":
				if p != "rank" && p != "immutable" {
					fail("%s: rank entity with field policy %s", fa, p)
				}
			}
			if f.Type == "enum" && len(f.Values) == 0 {
				fail("%s: enum without values", fa)
			}
			if f.Type != "enum" && len(f.Values) > 0 {
				fail("%s: values on a non-enum", fa)
			}
			switch f.Type {
			case "paise":
				if !strings.HasSuffix(fn, "_paise") {
					fail("%s: money fields are named *_paise", fa)
				}
			case "qty_milli":
				if !strings.HasSuffix(fn, "_milli") {
					fail("%s: quantities are named *_milli", fa)
				}
			case "bp":
				if !strings.HasSuffix(fn, "_bp") {
					fail("%s: rates are named *_bp", fa)
				}
			}
			if strings.HasSuffix(fn, "_paise") && f.Type != "paise" {
				fail("%s: *_paise must have type paise", fa)
			}
			if p == "rank" {
				hasRank = true
				if len(f.Order) < 2 {
					fail("%s: rank field needs an order list", fa)
				}
				if f.Type == "enum" {
					for _, o := range f.Order {
						if !contains(f.Values, o) {
							fail("%s: rank order value %s is not an enum value", fa, o)
						}
					}
					if len(f.Order) != len(f.Values) {
						fail("%s: rank order must list every enum value", fa)
					}
				}
			}
			if p == "delta" && f.Type != "qty_milli" && f.Type != "int" && f.Type != "paise" {
				fail("%s: delta policy needs a numeric type", fa)
			}
			if p == "lww_review" && f.Group == "" {
				fail("%s: lww_review needs a group (the stamp is kept per field group)", fa)
			}
			if f.PII && (f.Type == "paise" || f.Type == "bp" || f.Type == "qty_milli" || f.DocNumber || moneyish.MatchString(fn)) {
				fail("%s: no money, tax or numbering field may be pii (ADR-0002 S4)", fa)
			}
			if f.DocNumber && p != "immutable" {
				fail("%s: a legal document number is immutable", fa)
			}
			if f.Ref != "" {
				if _, ok := ents[f.Ref]; !ok {
					fail("%s: references unknown entity %s", fa, f.Ref)
				}
				if f.Type != "id" {
					fail("%s: ref on a non-id field", fa)
				}
			}
		}
		if e.Policy == "rank" && !hasRank {
			fail("%s: rank entity without a rank field", at)
		}
		if e.Guarded && e.Owner != "billing" && e.Owner != "orders" {
			fail("%s: guarded (money or tax) entities belong to billing or orders", at)
		}
		if e.Owner == "billing" && e.Policy == "append" && !e.Guarded && !strings.HasPrefix(name, "day_open") && !strings.HasPrefix(name, "tax_rule") {
			fail("%s: billing append entities are guarded unless they carry no money or tax", at)
		}
	}
	return errs, len(ents)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]entity) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func sortedFieldKeys(m map[string]field) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
