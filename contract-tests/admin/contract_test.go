// Package admin holds the contract suite for the admin API. It runs against the real service
// or its double: set HOSTRY_CONTRACT_BASE_URL. The admin API authenticates by session cookie, so
// set HOSTRY_CONTRACT_COOKIE to a test-issued session cookie (never a real one) and
// HOSTRY_CONTRACT_EXPECT_EXAMPLES=1 for a double.
package admin

import (
	"net/http"
	"os"
	"testing"

	"github.com/hostryhq/api-specs/contracttest"
)

func TestContract(t *testing.T) {
	base := os.Getenv("HOSTRY_CONTRACT_BASE_URL")
	if base == "" {
		t.Skip("HOSTRY_CONTRACT_BASE_URL not set")
	}
	h := http.Header{}
	if c := os.Getenv("HOSTRY_CONTRACT_COOKIE"); c != "" {
		h.Set("Cookie", c)
	}
	h.Set("Origin", base) // same-origin, as the browser sends it
	contracttest.Run(t, contracttest.Options{
		SpecPath: "../../openapi/admin/v1/openapi.yaml", BaseURL: base, Header: h,
		ExpectExamples: os.Getenv("HOSTRY_CONTRACT_EXPECT_EXAMPLES") == "1",
	})
}
