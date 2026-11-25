package reference_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hostryhq/api-specs/tax/reference"
)

type vector struct {
	ID            string          `json:"id"`
	Title         string          `json:"title"`
	Note          string          `json:"note"`
	CAConfirm     bool            `json:"ca_confirm"`
	Kind          string          `json:"kind"`
	Invariant     string          `json:"invariant"`
	Input         json.RawMessage `json:"input"`
	Expected      json.RawMessage `json:"expected"`
	ExpectedError string          `json:"expected_error"`
	SpecExpect    map[string]any  `json:"spec_expect"`
}

type file struct {
	CalcV int      `json:"calc_v"`
	Cases []vector `json:"cases"`
}

type creditInput struct {
	Original reference.Bill         `json:"original"`
	Credit   []reference.CreditLine `json:"credit"`
}

func load(t *testing.T) file {
	t.Helper()
	b, err := os.ReadFile("../conformance/vectors.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// Every vector must be reproduced to the paisa by an implementation that did not generate it.
func TestConformanceVectors(t *testing.T) {
	f := load(t)
	if f.CalcV != reference.CalcV {
		t.Fatalf("vectors are for calc_v %d, reference implements %d", f.CalcV, reference.CalcV)
	}
	for _, v := range f.Cases {
		t.Run(v.ID, func(t *testing.T) {
			var got, want any
			var err error
			switch v.Kind {
			case "bill":
				var in reference.Bill
				must(t, json.Unmarshal(v.Input, &in))
				var r reference.Result
				r, err = reference.Calculate(in)
				got = r
				if v.ExpectedError == "" {
					var w reference.Result
					must(t, json.Unmarshal(v.Expected, &w))
					want = w
				}
			case "credit_note":
				var in creditInput
				must(t, json.Unmarshal(v.Input, &in))
				var r reference.CreditResult
				r, err = reference.CalculateCredit(in.Original, in.Credit)
				got = r
				if v.ExpectedError == "" {
					var w reference.CreditResult
					must(t, json.Unmarshal(v.Expected, &w))
					want = w
				}
				if v.Invariant == "totals_equal_original" {
					bill, berr := reference.Calculate(in.Original)
					must(t, berr)
					if r.TotalPaise != bill.TotalPaise || r.CGSTPaise != bill.CGSTPaise || r.SGSTPaise != bill.SGSTPaise || r.RoundOffPaise != bill.RoundOffPaise {
						t.Errorf("a full credit note must equal the bill: credit %+v vs bill total %d cgst %d sgst %d round-off %d", r, bill.TotalPaise, bill.CGSTPaise, bill.SGSTPaise, bill.RoundOffPaise)
					}
				}
			default:
				t.Fatalf("unknown kind %q", v.Kind)
			}
			if v.ExpectedError != "" {
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("want error %q, got %v", v.ExpectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.SpecExpect != nil {
				// The figures stated by the acceptance criteria of the restaurant spec (section 8.2).
				raw, _ := json.Marshal(got)
				var m map[string]any
				must(t, json.Unmarshal(raw, &m))
				for k, w := range v.SpecExpect {
					switch k {
					case "ref":
					case "alloc":
						var alloc []any
						for _, l := range m["lines"].([]any) {
							alloc = append(alloc, l.(map[string]any)["bill_discount_alloc_paise"])
						}
						if !reflect.DeepEqual(alloc, w) {
							t.Errorf("%s: allocation %v, spec says %v", v.SpecExpect["ref"], alloc, w)
						}
					default:
						if m[k] != w {
							t.Errorf("%s: %s is %v, spec says %v", v.SpecExpect["ref"], k, m[k], w)
						}
					}
				}
			}
			if !reflect.DeepEqual(got, want) {
				g, _ := json.MarshalIndent(got, "", " ")
				w, _ := json.MarshalIndent(want, "", " ")
				t.Fatalf("mismatch\n got: %s\nwant: %s", g, w)
			}
		})
	}
}

// The suite must cover what the work package names, and every rule that needs the CA must say so.
func TestVectorCoverageAndCAFlags(t *testing.T) {
	f := load(t)
	if len(f.Cases) < 40 {
		t.Fatalf("%d vectors, want at least 40", len(f.Cases))
	}
	need := map[string]string{
		"CGST/SGST split": "cgst", "rounding": "half up", "discount before tax": "discount", "service charge": "service charge",
		"inclusive": "inclusive", "exclusive": "exclusive", "complimentary": "complimentary", "credit note reversal": "credit note",
	}
	for topic, key := range need {
		found := false
		for _, v := range f.Cases {
			if strings.Contains(strings.ToLower(v.Title+" "+v.Note), key) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no vector covers %s", topic)
		}
	}
	seen := map[string]bool{}
	for _, v := range f.Cases {
		if seen[v.ID] {
			t.Errorf("duplicate vector id %s", v.ID)
		}
		seen[v.ID] = true
		if v.CAConfirm && !strings.Contains(v.Note, "CA") {
			t.Errorf("%s needs CA confirmation but its note does not say so", v.ID)
		}
	}
}

func TestErrorsAreTyped(t *testing.T) {
	_, err := reference.Calculate(reference.Bill{Regime: "regular", PriceMode: "exclusive",
		Rules: map[string]reference.Rule{"c": {GST: true, CGSTbp: 250, SGSTbp: 250}},
		Lines: []reference.Line{{ID: "a", QtyMilli: 1000, UnitPricePaise: 100, TaxClass: "c", Discount: &reference.Discount{Kind: "amount", Value: 101}}}})
	if !errors.Is(err, reference.ErrDiscountExceedsValue) {
		t.Fatalf("got %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
