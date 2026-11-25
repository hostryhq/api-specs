# api-specs

OpenAPI contracts and event schemas, the source of truth for every Hostry service API.
Change the contract first, then regenerate, then implement (`api-contract-standard`).

## Layout
```
openapi/<service>/v1/openapi.yaml   one OpenAPI 3.1 document per service and major version (sync: /sync/v1 device operations and the internal emit)
sync/protocol-v1.md                 normative sync rules a schema cannot state (hashing, chain, seal, size limit, the op event, emit)
sync/conformance/v1.json            shared vectors for the Go and TypeScript sync engines
sync/intents/                       sync intent registry (device and cloud-origin intents)
events/sync/                        gateway events: sync.op.<namespace> (whole op), quarantine.recorded, op.flagged, pii.erased
examples/worlds/<domain>.yaml       one shared example world per domain: ids, GSTINs, series codes, members, devices (make lint-worlds)
common/vendor-grant.vectors.v1.json subject-hash and example-grant vectors for the vendor approval grant (ADR-0014 A2.6)
common/components.yaml              shared Problem, Money, Id, phone/GSTIN/ticket formats, cursor + Idempotency-Key + header params, error responses
common/permissions.yaml             permission catalogue (flags), vendor roles, link scopes
events/_envelope.v1.yaml            ADR-0011 envelope (JSON Schema)
events/<service>/<entity>.<verb>.v<N>.yaml   one schema per event; declares x-publisher / x-subscribers
common/exceptions.yaml              shared detector-result (Exception) schema for catalog, orders, billing
common/vendor.yaml                  vendor approval grant header and If-Match for /internal/v1/vendor writes
entities/<product>/<entity>.yaml    synced entity schemas: owner service, stream, conflict policy per field (README inside)
tax/                                tax calculation spec (calc_v), rule-set schema, conformance vectors, Go reference
contracttest/                       Go harness: runs a spec's examples against any base URL
contract-tests/<service>/           per-service suite (real service or its double/)
examples/ping/                      tiny spec + double proving the harness
```
Status of each document is `info.x-status` (`draft`, `stable`, `deprecated`). Identity, tenancy, admin, catalog, orders and billing are `stable` v1 (catalog, orders and billing and the Admin A1 additions to tenancy are Phase 2 drafts of the contract, stable in the sense that servers and doubles are built against them).
Tenant-facing paths are under `/v1`; operations for other services and for the admin service are under `/internal/v1`
(ADR-0005 section 9) and declare `x-service-callers`. Wire details fixed with go-auth: user, vendor and support tokens in
`Authorization: Bearer`, service token in `Hostry-Service-Token`, approval token in `Hostry-Approval`, any refused token is
401 `auth.invalid_token`. Extensions: `x-permission`, `x-step-up`, `x-outlet-scoped`, `x-service-callers`, `x-vendor-class`,
`x-vendor-audit` (`none` only on directory-class reads), `x-feature-flag: LINKS_ENABLED`, `x-example-world` (see
`docs/conventions.md`).

## Conventions the lint enforces (`.spectral.yaml`)
`/v1` kebab-case plural paths; `operationId` lowerCamelCase; `x-permission` on every operation (`public`
for unauthenticated); `Idempotency-Key` on mutations; every schema property described; examples on every
request/response body; errors are `application/problem+json` only; no `tenant_id` in request bodies;
`*_paise` fields are integers. Errors follow go-common: `type` = `urn:hostry:problem:<code>`, plus `code`,
`request_id`, `errors[{field,code,message}]`. Idempotency-Key is 1-128 visible ASCII; reuse with a
different request is 422 `idempotency.mismatch`, while in progress 409 `idempotency.in_progress`.
Lists use `cursor`/`limit` and return `items` plus `next_cursor` (absent on the last page).

## Make targets
Tools install locally (`make tools` puts Go tools in `.tools/bin`; Node tools run via pinned `npx`).

| Target | Does |
|---|---|
| `make lint` | Spectral on all specs + event schemas and examples + `validate-specs` (catalogue flags, realms, callers, vendor-audit marker) + `validate-entities` (entity owners, policies, references, pii, replicas) + `validate-intents` (registry, `x-emits-intent`, emit callers, generated `sync.op` subscribers) + `validate-worlds` (every example against the shared worlds) |
| `make breaking` | oasdiff against `BASE` (default `origin/main`); breaking changes fail |
| `make generate` | bundle, then Go (`gen/go/<service>/`, oapi-codegen: types, net/http server, client) and TypeScript (`gen/ts/<service>.d.ts`, openapi-typescript) |
| `make test` | `go vet` and tests, including the harness self-test |

`gen/` and `build/` are not committed; CI regenerates from tagged spec versions.

## Contract tests
```go
srv := httptest.NewServer(double.New()) // or the real service's URL
contracttest.Run(t, contracttest.Options{
    SpecPath: "path/to/openapi.yaml", BaseURL: srv.URL,
    Header: http.Header{"Authorization": {"Bearer " + token}}, // test-issuer token only
    ExpectExamples: true, // doubles must serve the spec's examples
})
```
It checks status, media type, schema validity, idempotent replay and the unknown-route problem response.
Requests are built from spec examples, so the target must be seeded to match them. Examples hold in named
worlds (`info.x-example-worlds`, per-operation `x-example-world`); set `SeedWorld` to put a stateful target
into each operation's world before it is called (`docs/conventions.md`). The harness sends a distinct
`Idempotency-Key` per operation (`<operationId>:<example key>`).
