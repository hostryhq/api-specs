package contracttest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hostryhq/api-specs/contracttest"
	"github.com/hostryhq/api-specs/examples/ping/double"
)

const spec = "../examples/ping/openapi.yaml"

// The example double must pass the harness, serving the spec's examples.
func TestPingDoublePassesContract(t *testing.T) {
	srv := httptest.NewServer(double.New())
	defer srv.Close()
	contracttest.Run(t, contracttest.Options{SpecPath: spec, BaseURL: srv.URL, ExpectExamples: true})
}

// The harness must catch a server that drifts from the contract.
func TestHarnessDetectsViolations(t *testing.T) {
	good := double.New()
	bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/pings/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"not-an-id"}`)) // missing fields, bad id
		case r.Method == http.MethodGet && r.URL.Path == "/v1/pings":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			good.ServeHTTP(w, r)
		}
	})
	srv := httptest.NewServer(bad)
	defer srv.Close()

	reports, err := contracttest.Verify(context.Background(), contracttest.Options{SpecPath: spec, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	failed := map[string]bool{}
	for _, r := range reports {
		failed[r.OperationID] = len(r.Failures) > 0
	}
	for op, want := range map[string]bool{"getPing": true, "listPings": true, "createPing": false, "unknown-route": false} {
		if failed[op] != want {
			t.Errorf("%s: failed=%v, want %v", op, failed[op], want)
		}
	}
}
