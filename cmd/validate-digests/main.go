// Command validate-digests recomputes the projection digests (algorithm sha256-canon-v1, sync/protocol-v1.md) of the digest
// example worlds in examples/digests and compares them with the 200 example of the operation each fixture names. A fixture
// holds the exact rows of one outlet business day; every row is checked against its entity schema (entities/) first, so an
// example cannot describe a row the sync registry would refuse. Usage: validate-digests <repo-root> [-print].
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/hostryhq/api-specs/internal/canon"
)

type fixture struct {
	World       string                               `json:"world"`
	Spec        string                               `json:"spec"`
	OperationID string                               `json:"operation_id"`
	OutletID    string                               `json:"outlet_id"`
	Date        string                               `json:"business_date"`
	Rows        map[string]map[string]map[string]any `json:"rows"`
	// Commitments holds, per entity, row id and pii field, the salted commitment the sealed body carries (ADR-0014 A3.2). The
	// digest covers the commitment and never a value, so a fixture has no pii values.
	Commitments map[string]map[string]map[string]string `json:"commitments"`
}

type entity struct {
	Owner  string `yaml:"owner"`
	Fields map[string]struct {
		Type     string   `yaml:"type"`
		Required bool     `yaml:"required"`
		Values   []string `yaml:"values"`
		PII      bool     `yaml:"pii"`
	} `yaml:"fields"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-digests <repo-root> [-print]")
		os.Exit(2)
	}
	root, printOnly := os.Args[1], len(os.Args) > 2 && os.Args[2] == "-print"
	files, _ := filepath.Glob(filepath.Join(root, "examples", "digests", "*.json"))
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: no digest fixtures")
		os.Exit(1)
	}
	bad := 0
	for _, f := range files {
		errs := check(root, f, printOnly)
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "FAIL: %s: %s\n", filepath.Base(f), e)
		}
		bad += len(errs)
	}
	if bad > 0 {
		os.Exit(1)
	}
	fmt.Printf("digests: %d fixtures; every digest example equals the digest recomputed from its rows\n", len(files))
}

func check(root, file string, printOnly bool) (errs []string) {
	b, err := os.ReadFile(file)
	if err != nil {
		return []string{err.Error()}
	}
	var fx fixture
	if err := json.Unmarshal(b, &fx); err != nil {
		return []string{err.Error()}
	}
	digests := map[string][2]string{}
	type ed struct {
		Entity   string `json:"entity" yaml:"entity"`
		RowCount int    `json:"row_count" yaml:"row_count"`
		Hash     string `json:"hash" yaml:"hash"`
	}
	var list []ed
	names := make([]string, 0, len(fx.Rows))
	for n := range fx.Rows {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		eb, err := os.ReadFile(filepath.Join(root, "entities", "restaurant", n+".yaml"))
		if err != nil {
			errs = append(errs, "unknown entity "+n)
			continue
		}
		var ent entity
		if err := yaml.Unmarshal(eb, &ent); err != nil {
			errs = append(errs, n+": "+err.Error())
			continue
		}
		pii := map[string]bool{}
		for fn, f := range ent.Fields {
			pii[fn] = f.PII
		}
		texts := map[string]string{}
		for id, row := range fx.Rows[n] {
			for fn, f := range ent.Fields {
				if _, ok := row[fn]; f.Required && !ok {
					errs = append(errs, fmt.Sprintf("%s %s: required field %s missing", n, id, fn))
				}
			}
			for fn, v := range row {
				f, ok := ent.Fields[fn]
				if !ok {
					errs = append(errs, fmt.Sprintf("%s %s: field %s is not in the entity", n, id, fn))
					continue
				}
				if len(f.Values) > 0 {
					s, _ := v.(string)
					found := false
					for _, x := range f.Values {
						found = found || x == s
					}
					if !found {
						errs = append(errs, fmt.Sprintf("%s %s: %s=%v not in %v", n, id, fn, v, f.Values))
					}
				}
			}
			for fn, c := range fx.Commitments[n][id] {
				if f, ok := ent.Fields[fn]; !ok || !f.PII {
					errs = append(errs, fmt.Sprintf("%s %s: commitment for %s, which is not a pii field", n, id, fn))
				} else if len(c) != 64 {
					errs = append(errs, fmt.Sprintf("%s %s: commitment for %s is not 64 hex characters", n, id, fn))
				}
			}
			for fn := range row {
				if pii[fn] {
					errs = append(errs, fmt.Sprintf("%s %s: pii field %s carries a value; a digest fixture holds commitments only", n, id, fn))
				}
			}
			t, err := canon.RowText(id, row, pii, fx.Commitments[n][id])
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s %s: %v", n, id, err))
				continue
			}
			texts[id] = t
		}
		count, h := canon.EntityHash(texts)
		digests[n] = [2]string{fmt.Sprint(count), h}
		list = append(list, ed{n, count, h})
	}
	state := canon.StateHash(digests)
	if printOnly {
		out, _ := json.MarshalIndent(map[string]any{"state_hash": state, "entities": list}, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	// the example of the operation
	sb, err := os.ReadFile(filepath.Join(root, fx.Spec))
	if err != nil {
		return append(errs, err.Error())
	}
	var doc map[string]any
	if err := yaml.Unmarshal(sb, &doc); err != nil {
		return append(errs, err.Error())
	}
	ex := findExample(doc, fx.OperationID)
	if ex == nil {
		return append(errs, "no 200 example for "+fx.OperationID)
	}
	if ex["state_hash"] != state {
		errs = append(errs, fmt.Sprintf("state_hash example %v, recomputed %s", ex["state_hash"], state))
	}
	if ex["outlet_id"] != fx.OutletID || ex["business_date"] != fx.Date {
		errs = append(errs, "outlet_id or business_date of the example differ from the fixture")
	}
	got, _ := ex["entities"].([]any)
	if len(got) != len(list) {
		errs = append(errs, fmt.Sprintf("example lists %d entities, fixture has %d", len(got), len(list)))
		return errs
	}
	for i, e := range list {
		m, _ := got[i].(map[string]any)
		if m["entity"] != e.Entity || m["row_count"] != e.RowCount || m["hash"] != e.Hash {
			errs = append(errs, fmt.Sprintf("entity %s: example %v, recomputed %d rows %s", e.Entity, m, e.RowCount, e.Hash))
		}
	}
	return errs
}

func findExample(doc map[string]any, op string) map[string]any {
	paths, _ := doc["paths"].(map[string]any)
	for _, p := range paths {
		pm, _ := p.(map[string]any)
		for _, m := range pm {
			mm, _ := m.(map[string]any)
			if mm["operationId"] != op {
				continue
			}
			r, _ := mm["responses"].(map[string]any)
			r200, _ := r["200"].(map[string]any)
			c, _ := r200["content"].(map[string]any)
			j, _ := c["application/json"].(map[string]any)
			e, _ := j["example"].(map[string]any)
			return e
		}
	}
	return nil
}
