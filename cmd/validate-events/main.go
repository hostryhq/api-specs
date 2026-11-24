// Command validate-events checks every event schema under a directory: it compiles
// (envelope included), declares x-publisher matching its directory, and every embedded
// example validates against the schema. Usage: validate-events <events-dir>.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-events <events-dir>")
		os.Exit(2)
	}
	if errs := validate(os.Args[1]); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "FAIL:", e)
		}
		os.Exit(1)
	}
	fmt.Println("events: all schemas compile and all examples validate")
}

type doc struct {
	path string
	id   string
	raw  map[string]any
}

func validate(dir string) []string {
	var errs []string
	var docs []doc
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := yaml.Unmarshal(b, &m); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		id, _ := m["$id"].(string)
		if id == "" {
			errs = append(errs, p+": missing $id")
			return nil
		}
		docs = append(docs, doc{p, id, m})
		return nil
	})
	if err != nil {
		return append(errs, err.Error())
	}

	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for _, d := range docs {
		inst, err := toInstance(d.raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", d.path, err))
			continue
		}
		if err := c.AddResource(d.id, inst); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", d.path, err))
		}
	}
	for _, d := range docs {
		if strings.HasPrefix(filepath.Base(d.path), "_") {
			continue // envelope
		}
		// <dir>/<service>/<entity>.<verb>.v<N>.yaml; x-publisher must be the directory.
		if pub, _ := d.raw["x-publisher"].(string); pub == "" || pub != filepath.Base(filepath.Dir(d.path)) {
			errs = append(errs, d.path+": x-publisher must equal the service directory")
		}
		if _, ok := d.raw["x-subscribers"]; !ok {
			errs = append(errs, d.path+": missing x-subscribers")
		}
		sch, err := c.Compile(d.id)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", d.path, err))
			continue
		}
		examples, _ := d.raw["examples"].([]any)
		if len(examples) == 0 {
			errs = append(errs, d.path+": no examples")
		}
		for i, ex := range examples {
			inst, err := toInstance(ex)
			if err == nil {
				err = sch.Validate(inst)
			}
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: example %d: %v", d.path, i, err))
			}
		}
	}
	return errs
}

// toInstance round-trips through JSON so numbers and maps have the shapes jsonschema expects.
func toInstance(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(b))
}
