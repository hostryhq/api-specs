package contracttest_test

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// Every service contract must load with its external $refs and validate, examples included.
func TestServiceSpecsAreValid(t *testing.T) {
	for _, svc := range []string{"identity", "tenancy", "admin", "catalog", "orders", "billing", "sync"} {
		t.Run(svc, func(t *testing.T) {
			loader := openapi3.NewLoader()
			loader.IsExternalRefsAllowed = true
			doc, err := loader.LoadFromFile("../openapi/" + svc + "/v1/openapi.yaml")
			if err != nil {
				t.Fatal(err)
			}
			if err := doc.Validate(context.Background()); err != nil {
				t.Fatal(err)
			}
			if doc.Info.Extensions["x-status"] == "draft" {
				t.Fatal("spec is still draft")
			}
		})
	}
}
