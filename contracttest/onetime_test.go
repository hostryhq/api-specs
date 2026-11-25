package contracttest

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// A one-time secret is shown once and never stored, so a replay omits it; the replay check must ignore it and its flag only.
func TestStripOneTimeRemovesMarkedFieldAndFlag(t *testing.T) {
	secret := openapi3.NewStringSchema()
	secret.Extensions = map[string]any{"x-one-time-secret": map[string]any{"withheld_flag": "secret_withheld"}}
	sch := openapi3.NewObjectSchema().WithProperty("code", secret).WithProperty("n", openapi3.NewIntegerSchema())
	resp := openapi3.NewResponse().WithJSONSchema(sch)
	if got := string(stripOneTime(resp, []byte(`{"code":"X","secret_withheld":true,"n":1}`))); got != `{"n":1}` {
		t.Fatalf("got %s", got)
	}
}
