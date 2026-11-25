# api-specs tooling. CLI tools are installed locally (no global changes):
#   Go tools into .tools/bin via `make tools`; Node tools run through pinned npx.
SHELL := /bin/bash
SERVICES := identity tenancy admin
SPECS := $(foreach s,$(SERVICES),openapi/$(s)/v1/openapi.yaml)
LINT_SPECS := $(SPECS) examples/ping/openapi.yaml
BASE ?= origin/main

OAPI_CODEGEN_VERSION := v2.9.0
OASDIFF_VERSION := v1.39.0
SPECTRAL_VERSION := 6.17.1
REDOCLY_VERSION := 2.83.0
OPENAPI_TS_VERSION := 7.13.0

TOOLS := $(CURDIR)/.tools/bin
export PATH := $(TOOLS):$(PATH)

.PHONY: tools lint lint-events lint-specs breaking bundle generate generate-go generate-ts test clean

tools:
	GOBIN=$(TOOLS) go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)
	GOBIN=$(TOOLS) go install github.com/oasdiff/oasdiff@$(OASDIFF_VERSION)

# Spectral (Hostry rules in .spectral.yaml) + event schema and example validation.
lint: lint-events lint-specs
	npx --yes @stoplight/spectral-cli@$(SPECTRAL_VERSION) lint --fail-severity=warn $(LINT_SPECS)

lint-events:
	go run ./cmd/validate-events events

# Cross-document conventions: permission catalogue, realms, x-service-callers, x-vendor-audit.
lint-specs:
	go run ./cmd/validate-specs .

# Breaking-change diff against $(BASE) (default origin/main) using oasdiff.
# A spec absent on the base is new and skipped. Breaking changes need a new /v2 path.
breaking:
	@set -e; \
	if ! git rev-parse --verify -q $(BASE) >/dev/null; then echo "base $(BASE) not found; skipping"; exit 0; fi; \
	tmp=$$(mktemp -d); trap 'rm -rf $$tmp' EXIT; \
	git archive $(BASE) common openapi 2>/dev/null | tar -x -C $$tmp || { echo "no openapi/ on $(BASE); nothing to compare"; exit 0; }; \
	for s in $(SPECS); do \
	  if [ -f $$tmp/$$s ]; then echo "== $$s"; oasdiff breaking --fail-on ERR $$tmp/$$s $$s; \
	  else echo "== $$s is new on this branch; skipped"; fi; \
	done

# Inline shared $refs so generators see a single document per service.
bundle:
	@mkdir -p build
	@for s in $(SERVICES); do \
	  npx --yes @redocly/cli@$(REDOCLY_VERSION) bundle openapi/$$s/v1/openapi.yaml -o build/$$s.yaml >/dev/null || exit 1; done
	@npx --yes @redocly/cli@$(REDOCLY_VERSION) bundle examples/ping/openapi.yaml -o build/ping.yaml >/dev/null

# Outputs (gitignored; CI regenerates from tagged spec versions):
#   gen/go/<service>/<service>.gen.go  types + net/http server + client (oapi-codegen)
#   gen/ts/<service>.d.ts              TypeScript types (openapi-typescript)
generate: generate-go generate-ts

generate-go: bundle
	@for s in $(SERVICES); do mkdir -p gen/go/$$s; \
	  oapi-codegen -generate types,std-http-server,client -package $$s -o gen/go/$$s/$$s.gen.go build/$$s.yaml || exit 1; done
	go build ./gen/...

generate-ts: bundle
	@mkdir -p gen/ts
	@for s in $(SERVICES); do \
	  npx --yes openapi-typescript@$(OPENAPI_TS_VERSION) build/$$s.yaml -o gen/ts/$$s.d.ts || exit 1; done

test:
	go vet ./...
	go test ./...

clean:
	rm -rf build gen
