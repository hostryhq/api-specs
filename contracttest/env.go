package contracttest

import (
	"net/http"
	"os"
	"testing"
)

// RunFromEnv runs the contract against HOSTRY_CONTRACT_BASE_URL (skipping when unset), with an
// optional bearer token from HOSTRY_CONTRACT_TOKEN (a test-issuer token, never a real one).
// Service repos normally call Run directly with their double's httptest server URL.
func RunFromEnv(t *testing.T, specPath string, expectExamples bool) {
	t.Helper()
	base := os.Getenv("HOSTRY_CONTRACT_BASE_URL")
	if base == "" {
		t.Skip("HOSTRY_CONTRACT_BASE_URL not set")
	}
	h := http.Header{}
	if tok := os.Getenv("HOSTRY_CONTRACT_TOKEN"); tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	Run(t, Options{SpecPath: specPath, BaseURL: base, Header: h, ExpectExamples: expectExamples})
}
