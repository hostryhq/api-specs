// Package tenancy holds the contract suite for the tenancy API. It runs against the real
// service or its double: set HOSTRY_CONTRACT_BASE_URL (and HOSTRY_CONTRACT_TOKEN).
// Draft: the spec is a skeleton; the next wave fills it in.
package tenancy

import (
	"testing"

	"github.com/hostryhq/api-specs/contracttest"
)

func TestContract(t *testing.T) {
	contracttest.RunFromEnv(t, "../../openapi/tenancy/v1/openapi.yaml", false)
}
