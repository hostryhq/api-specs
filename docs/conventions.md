# Contract conventions

Rules that go beyond `.spectral.yaml`. The lint in `cmd/validate-specs` enforces the ones marked (lint).

## `x-permission` modes

Every operation declares exactly one `x-permission`. Three forms exist:

| Value | Meaning | Who may call | Notes |
|---|---|---|---|
| a catalogue key, for example `member.read` | The caller needs that permission (`common/permissions.yaml`). Checks are on permissions, never role names. | A token of the realm the key belongs to (tenant, vendor or service) | Step-up (`x-step-up`), outlet scope (`x-outlet-scoped`) and support-session flags apply as the catalogue says. (lint) |
| `authenticated` | Any valid access token of the operation's realm is enough; no catalogue permission is checked. | Tenant-facing operations: a user, PIN or device token of the caller's organisation (the security scheme on the operation decides which). Vendor operations: a vendor token. | The operation still derives the tenant from the token, answers 404 for another tenant's object, and does its own object-level checks (for example, only the caller's own member record). Use it for reference data and self-service operations only; anything that changes another principal's data needs a catalogue key. |
| `public` | No access token. The operation declares `security: []` (or only the service scheme, see below) and authenticates, if at all, by a credential in the request: an OTP, a refresh token, a device assertion, a setup token. | Anyone who can reach the route | Rate limits and identical-answer rules (no enumeration) are part of each operation's text. A tenant id is never accepted from the request. |
| `public` with `x-service-callers` | The user has no token yet (vendor sign-in, vendor setup), so the route takes no vendor token, but it is reachable **only through the named service**: the request must carry a valid `Hostry-Service-Token` from a caller listed in `x-service-callers`. | The admin service, on behalf of a browser session | A browser can never call it directly. |

`x-service-callers` lists the services allowed to call an `/internal/v1` operation, as service names; the single entry `'*'` means any service holding a valid service token (for example the link-decision read that go-auth makes). It appears on `/internal/v1` operations and on no others. (lint)

go-auth carries matching `Policy` modes (any-caller `"*"`, authenticated-only, public with named callers); until it does, services enforce these rules in their own middleware and the contract tests prove them.

## Example worlds

A contract example is only true in some state of the world: a link is `proposed` before it is `active`, a registration is `unverified` until staff verify it. One spec therefore cannot show every operation in one single state, and a stateful double cannot serve an example whose precondition is false. So:

- `info.x-example-worlds` declares named fixtures, each with a prose description precise enough to seed a service or a double: which entities exist (by the ids used in the examples), their states, who the caller is, and which feature flags are on. `base` must exist. (lint)
- An operation may carry `x-example-world: <name>`; without it the world is `base`. The name must be declared. (lint)
- **All examples of one operation (request, parameters, every response) describe that operation in its world, before the call**, with the response showing the state after it. Ids are consistent across the whole document: one id names one entity, and the same entity has the same fields in every world that contains it, except for the state the world is there to vary.
- Creating operations use ids that do not exist in their world; server-generated ids in responses (for example a session id) are the values the double must mint.
- Pagination examples use the shared `cursor` example, which decodes to `{"after": "<a UUIDv7 below every example id>"}`, so a page after it contains every seeded row.
- Examples are real values: GSTINs carry a correct check character, series codes are 3 characters from the registry alphabet, role permissions are catalogue keys, `catalogue_version` is the catalogue's, `body_hash` is a true SHA-256.

The contract harness (`contracttest`) calls `Options.SeedWorld(ctx, world)` before each operation so the target can be put in that state (a double resets and loads the fixture; a real service runs its seed script). When `SeedWorld` is nil, the target must already satisfy every operation, which only holds for a read-only or single-world target. With `ExpectExamples` a double must return a body equal to the operation's response example.

The harness sends `Idempotency-Key: <operationId>:<example key>` so keys never collide across operations on one target; the replay check reuses the same key. A double implementing replay must not treat that as a different request.

## Identifiers, formats and examples

- IDs are UUIDv7 in lower-case canonical form (`common/components.yaml` `Id`); ULID is not accepted (ADR-0003 policy).
- GSTIN examples must pass the check-character rule. `33ABCDE1234F1Z7`, `33AAAAA0000A1Z9` and `29ABCDE1234F1ZW` are valid; do not invent others without computing the check character.
- Document series codes are three characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no `I`, `O`, `0`, `1`; ADR-0002 S7 and the registry). The ADR's own example `A07` contains a `0` and is superseded by the registry alphabet; the architect is to correct the ADR text.
- An approval's `body_hash` is `sha256:` plus the lower-case hex SHA-256 over the exact request body bytes as sent, with no re-serialisation (empty body: hash of the empty string). See `ApprovalRequest.body_hash` in the identity spec.

## Shared example worlds (examples/worlds)

`examples/worlds/<domain>.yaml` (`platform`, `restaurant`, `sync`) declares every id, GSTIN, series code, member, device and fixed
fact once. `make lint-worlds` reads every spec, event, entity and registry document and fails on: an id no world declares; an id whose
kind does not fit its field (a vendor user as `member_id`); a GSTIN with a wrong check character or without a registration; a series
code outside the registry alphabet or without a series; an example entity whose `name`, `code`, `number` ... differ from the declared
facts; a deterministic row id (`id.rule: uuidv5`) that is not the UUIDv5 of its natural key (the entry carries `derive`); a duplicated
event example id; a `next_cursor` in a response example (a base-world list holds every row); a vector count that disagrees with
`tax/conformance`. A new example uses an id from the world or adds one there first. Example prose uses the last four hex digits.

## Cloud emit and intents (ADR-0014 A2.2, A2.3)

An operation that writes synced data from the cloud declares `x-emits-intent: <cloud-origin intent>` (owned by the same service,
its `x-permission` in the intent's `authorised_online_by`, checked both ways by `make lint-intents`) and, when interactive,
answers 503 `emit.unavailable` with `Retry-After` through the shared `EmitUnavailable` response. `POST /internal/v1/emit`
(`openapi/sync/v1`) is the only way a service writes to devices; its tenant is a body field because a service token carries none.
