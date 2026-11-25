// Package tenancy holds the contract suite for the tenancy API. It runs against the real
// service or its double: set HOSTRY_CONTRACT_BASE_URL (and HOSTRY_CONTRACT_TOKEN, a test-issuer token).
// Set HOSTRY_CONTRACT_EXPECT_EXAMPLES=1 for a double, which must serve the spec's examples.
// Requests are built from the spec examples, so the target must be seeded to match them.
package tenancy

import (
	"os"
	"testing"

	"github.com/hostryhq/api-specs/contracttest"
)

func TestContract(t *testing.T) {
	contracttest.RunFromEnv(t, "../../openapi/tenancy/v1/openapi.yaml", os.Getenv("HOSTRY_CONTRACT_EXPECT_EXAMPLES") == "1")
}
