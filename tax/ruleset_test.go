package tax_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func yamlToAny(t *testing.T, path string) any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	// round trip through JSON so the validator sees plain JSON types
	j, err := json.Marshal(normalise(v))
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(j, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func normalise(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = normalise(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = normalise(e)
		}
		return x
	}
	return v
}

// The example draft must satisfy the schema and the BR-A1-82 structural rules that the schema cannot state.
func TestDraftRuleSetIsValid(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("urn:hostry:tax:rule-set:v1", yamlToAny(t, "rule-set.schema.yaml")); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("urn:hostry:tax:rule-set:v1")
	if err != nil {
		t.Fatal(err)
	}
	doc := yamlToAny(t, "rule-sets/draft-unreviewed.v1.yaml")
	if err := sch.Validate(doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range doc.(map[string]any)["rules"].([]any) {
		m := r.(map[string]any)
		key := fmt.Sprint(m["tax_class"], "|", m["regime"], "|", m["specified_premises"], "|", m["order_channel"])
		if seen[key] {
			t.Errorf("two rules for %s", key)
		}
		seen[key] = true
		if m["cgst_bp"] != m["sgst_bp"] {
			t.Errorf("%s: components of an intra-state supply are two equal halves", key)
		}
		if m["gst_applies"] == false && (m["cgst_bp"].(float64) != 0) {
			t.Errorf("%s: a rule without GST carries a rate", key)
		}
	}
}
