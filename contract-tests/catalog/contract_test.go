// Package catalog holds the contract suite for the catalog API. It runs against the real service or its
// double: set HOSTRY_CONTRACT_BASE_URL (and HOSTRY_CONTRACT_TOKEN, a test-issuer token). Set
// HOSTRY_CONTRACT_EXPECT_EXAMPLES=1 for a double, which must serve the spec's examples. Requests are
// built from the spec examples, so the target must be seeded to match them. Operations that need the
// admin service token or a vendor approval grant are exercised by the service's own tests.
package catalog

import (
	"os"
	"testing"

	"github.com/hostryhq/api-specs/contracttest"
)

func TestContract(t *testing.T) {
	contracttest.RunFromEnv(t, "../../openapi/catalog/v1/openapi.yaml", os.Getenv("HOSTRY_CONTRACT_EXPECT_EXAMPLES") == "1")
}
