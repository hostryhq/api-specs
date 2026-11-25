# Sync Protocol v1: normative rules (ADR-0002 A2.3)

The contract of record for the sync wire. Machine-readable parts: `openapi/sync/v1/openapi.yaml` (HTTP surface, device
operations under `/sync/v1`, the internal emit operation under `/internal/v1`), `sync/conformance/v1.json` (shared vectors
for the Go and TypeScript engines, ADR-0002 S15), the entity registry is `entities/` (named `sync/entities` in ADR-0002 A2.3), the intent registry is `sync/intents/`,
and the bus events are `events/sync/`. This file holds the rules a schema cannot state: canonical form, hashing, chain,
seal, endorsement and attestation messages, LAN assertion and hub proof, hold codes, void encoding, the size limit and the
op event. `svc-sync/contract/` keeps only the Go contract suite, which reads these files at the pinned `api-specs` version.

**Change rule (ADR-0002 A2.3).** A change under `sync/` or `openapi/sync/` merges only with the Go and the TypeScript engine
green on the new vectors. A change to any signed or hashed message takes a new domain tag (`-v2`) and a protocol version;
`-v1` messages are never redefined.

## Framing and hashing
- An op travels as `Item{origin, stream, seq, h, body, pii}`. `body` is the **canonical JSON text of the op
  body as a JSON string**. Relays forward it byte for byte; every verifier hashes the UTF-8 bytes it
  received: `h = lowercase hex SHA-256(body)`. Nobody re-serialises (S17).
- Canonical form is RFC 8785 for the integer-only subset: sorted keys (UTF-16 order), no whitespace, minimal
  escapes, integers only within +-(2^53-1). Fractions and exponents are refused (money is paise).
- Chain: `ph` of op n is `h` of op n-1 of the same origin and stream; op 1 chains to
  `sha256("hostry-genesis-v1\n" + origin + "\n" + stream)`.
- Seal: ES256 (raw r||s, base64url) over `sha256("hostry-seal-v1\n" + origin + "\n" + stream + "\n" + seq + "\n" + h)`.
  A push group (origin, stream) must end at a sealed op; a node accepts nothing a valid seal does not cover.
  The hub and cloud serve ops only up to a seal boundary.
- **Endorsement (ADR-0002 A2.1; replaces the PoC rule "an op-signing key may seal any origin").** The released,
  previously unsealed tail of a key-lost origin has no origin seal. The gateway signs a separate object
  `endorsement = {origin, stream, seq, h, rec, kid, sig}`: ES256 by an op-signing key (`cloud_keys` of the pack, named
  by `kid`) over `sha256("hostry-endorse-v1\n" + origin + "\n" + stream + "\n" + seq + "\n" + h + "\n" + rec)`; `rec` is
  the recovery id. One endorsement per released op, made in the release transaction (a voided configuration op gets none).
  Wire fields: `endorsements` and `attestations` (arrays) in the pull response, in the push request and in the
  quarantine-upload; the adopting device's credential travels in `creds` of a pull. **Seal rule:** a signature by an
  op-signing key under the `hostry-seal-v1` tag is valid only for a `cloud-<epoch>` origin (the seal's `kid` selects the
  key; a key the node does not hold, or has revoked, verifies nothing). It never seals a device origin.
- **Verifier rule (hub, device, gateway; identical).** An op of origin X that no seal of X covers is accepted only if
  (1) an endorsement for exactly `(origin, stream, seq, h)` verifies under a *current* op-signing key; (2) the node holds
  an identity-signed credential of a device Y with `recovers: X`; (3) an attestation for `(X, stream)` with the same `rec`
  verifies under Y's key, the op's `seq` is at or below the attested `seq`, and the op the node holds (or has in the
  batch) at the attested `seq` has the attested `h`. The chain check (`ph`) does the rest, so the highest verified
  endorsement of a batch covers the chain below it. Every op accepted this way is marked `unsealed` in the node's audit
  views. Anything else unsealed is refused (`unsealed`).
- **Serving and relaying endorsements (the client must do this too).** An endorsement counts as a seal boundary: a hub,
  device or gateway cuts a served or pushed batch at a seal *or* an endorsement. A batch whose cut is an endorsement carries
  **every endorsement in the range** (not only the last), the last origin seal in the range (so that the sealed part stays
  unmarked), the stored attestation(s), and in a pull the credential(s) of the adopting device. A node therefore must
  *store* what it verified (endorsements, attestations) and re-serve it with the ops. A released op answered for a
  `placeholders` entry carries its endorsement, attestation and the credential the same way. A node holding the
  placeholder verifies an endorsement that arrives with the body by the rule above and marks the op `unsealed`; a body that
  arrives with no endorsement is an ordinary released slot and is taken by hash, as before A2 (a residual: the same upstream
  gave the placeholder's hash).
- **After a cloud restore (A2.1 item 5).** While its re-offer is open a node's push also carries `items` + `endorsements`
  (+ `attestations`) for endorsed ops *at or below* the cloud's vector. The gateway takes a slot it holds as `quarantined`
  (`unsealed_tail`) as released, marked `unsealed`, with no owner action, if endorsement, credential and attestation
  verify. Tail ops that come back without an endorsement go back to quarantine through the recovery re-upload.
- **Key rotation (A2.1 item 6).** After an emergency rotation the gateway re-signs its cloud-origin seals and every
  endorsement under the new key. A node refreshes its pack (adds the new `cloud_keys` entry, drops the old) and then
  lists any op whose stored endorsement is under a dropped key in `placeholders`; the answer carries the re-issued
  endorsement and replaces the stored one. A node that holds only the new key converges from the cloud (or from a hub
  that has refreshed).
- Vectors are flat maps keyed `origin/stream`. Placeholders (no `body`) fill held slots and carry `h`.

## Sync void (answer to "is the assumed encoding right")
Confirmed with one correction: intent `sync.void` from origin `cloud-<epoch>`, one mutation
`{e:"sync_void", id:"<stream>|<origin>|<seq>", k:"insert", f:{origin, stream, seq, reason:"refused"}}`. The `id`
is `stream|origin|seq` (the client's form; the gateway now emits exactly this). `reason` is always `refused`.
The void is sealed by the gateway like any cloud-origin op. A node adds the named op to its void set.

## Keys: how the op-signing key reaches clients
Through the **signed offline pack** (ADR-0005 section 6), as `cloud_keys: {kid: pub}` (X9.62 uncompressed P-256 point,
base64url), together with the identity verification key. Never through `hello` (trust on first use would
defeat the seal). `KeyRing.addCloudKey(kid, pub)` is the right entry. Seals carry `kid`.

## Authentication
- Cloud: `Authorization: Bearer` go-auth device token (typ `device`). Drain tokens only at
  `quarantine-upload`; a recovery drain token has subject `recovers:<old device id>`.
- LAN hub: `Hostry-Device-Assertion` = base64url JSON `{cred, ts, sig}`, `sig` over
  `sha256("hostry-lan-v1\n" + METHOD + "\n" + path + "\n" + ts + "\n" + hex SHA-256 of the request body bytes **as sent**
  (after gzip, if gzipped))`. The hub answers every call with `Hostry-Hub-Proof` = base64url JSON `{cred, sig}`, `sig`
  over `sha256("hostry-hub-v1\n" + requestSig + "\n" + hex SHA-256 of the response body)`. Timestamp window 2 minutes.
  TLS is not in the PoC.

## hello
- `snapshot_required` is always `false`; the PoC does not need a snapshot client (`GET /snapshot` exists in its
  simplest form for tooling).
- A hub's `cloud_vector` is what the cloud confirmed to **that hub** at its last upstream contact. A device may
  treat its ops under it as delivered to the cloud (`in_cloud` via the hub). Intended.
- `epoch` is the cloud epoch. **Re-offer (ADR-0002 A2.2).** Each node persists two meta values: `epoch` (the newest epoch
  heard from any upstream) and `reoffered_epoch` (the epoch it last finished re-offering for). The re-offer is **open** while
  they differ. A hub's `hello.epoch` may open it (when it differs from both values; a hub that repeats the already
  re-offered epoch is stale and ignored); the cloud's `hello.epoch` is authoritative. While it is open a device whose
  upstream is a hub also runs `hello` and push **against the cloud directly**, on its ordinary retry schedule, and keeps
  syncing with the hub: the hub may hold only a placeholder for a slot whose body the cloud lost, so the origin is the
  only node that can deliver it (simulator seed 1). The first push round of an open re-offer also carries the endorsed ops
  below the cloud's vector (above). **Closing:** only a direct cloud `hello` whose epoch equals the newest epoch, after
  which nothing is left to push, sets `reoffered_epoch = epoch`. An op the cloud refused (listed in `refused` of the push
  response) does not count as left to push, so one op refused for ever cannot hold the re-offer open. Every direct cloud
  contact for another reason (pack refresh, delivery of an op a hub will not relay) compares epoch and vector the same way.
  A device with no cloud route stays open; the gateway raises "unrecoverable origin gap" 24 hours after a node first reports
  a vector above the cloud's, and clears it when the node's vector is no longer above.

## Verdicts and read-back
Devices learn about their own held slots only as `held` (push) and `own_held` (pull) with one of
`pending | held_manager | held_support`, and about refused configuration only through the `sync.void` op.
Flags, reasons and attribution labels exist only behind member-token admin endpoints.

## Document numbers
`<code>/<FY>/<running>`, `code` 3 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no I, O, 0, 1), FY as four
digits, six-digit running number. ADR-0002 S7 excludes `0` yet shows `A07/...`; the registry rule is followed and
the example is not a valid code (the stub registry issues `AAA`, `AAB`, ...). The PoC intent registry is
`syncproto/intents.go`; it also lists the demo intent names the TypeScript client uses.

## Size limit (ADR-0014 A2.1 item 3; provisional, confirmed from the soak's op-size figures)
- An op's `body` is at most **262144 bytes (256 KiB)**, counted as the UTF-8 bytes of the JSON string that `h` covers; its
  `pii` object is at most **16384 bytes (16 KiB)** of canonical JSON. Vectors `size_limit` and `emit_batch` (1 to 200 ops per emit) in `sync/conformance/v1.json`.
- `client-core` refuses the action before anything is recorded or numbered (`op_too_large`; a bill that long is split). The
  emit operation refuses it (422 `op.too_large`, a defect in the caller). A device op over the limit that still arrives is
  malformed under ADR-0002 S11: quarantined as an opaque body, never dropped, never published with its body.
- The bus `max_payload` is set to 1 MiB by `infra`, explicitly.

## The op event on the bus (ADR-0014 A2.1; schema `events/sync/op.v1.yaml`)
- Type `sync.op.<namespace>`, namespace = the text before the first dot of the intent name; subject `evt.sync.op.<namespace>.v1`.
  A void is an op of intent `sync.void`, published under namespace `sync`.
- `data` = `origin`, `stream`, `seq`, `h`, `intent`, `intent_v`, `status` (`accepted` or `flagged`), `marks` (for example
  `unsealed`), `body` and `pii`. **`body` is the JSON string holding the exact bytes the origin sent and `h` was computed
  over**, never a re-serialised or upcast form; no op field is repeated beside it. Consumers read an op only through the
  shared parser (`go-common/sync.ParseOp`), which runs the upcasters (ADR-0002 S13).
- Envelope `key` = `<stream>|<origin>`, `key_seq` = `seq`, `outlet_id` set for an outlet stream. **A consumer does not wait
  for gaps and does not need order**: `seq` is sparse for a service (it sees only its namespaces) and the apply engine gives
  the same rows for any arrival order (a row whose parent is missing is parked, ADR-0002 S11).
- An op is published when it becomes applicable: at acceptance, or at release from quarantine. A quarantined op is never
  published with its body. `sync.quarantine.recorded` (series code, number and document type, no content) and
  `sync.op.flagged` (identity and coarse code) are id-only types.
- `pii` travels in the event (a stated exception to ADR-0011 B6). A consumer stores `pii` fields only for entities it owns,
  in an erasable side table, and never for a replica (`replicated_to`, ADR-0014 A2.4). `sync.pii.erased` (ids only) tells
  each owner to erase.

## Cloud-origin emit (ADR-0014 A2.2)
Operation `emitOps` (`POST /internal/v1/emit`) is the only way a service writes data to devices. The gateway alone stamps
`origin = cloud-<epoch>`, `seq`, `ph`, `hlc` and seals the batch; a caller never chooses them. It checks that the caller owns
the intent, the intent is cloud-origin, every mutation is of an entity and kind the intent lists, the stream belongs to the
tenant and the size limit. Idempotency is `(tenant_id, caller, key)` per op: same key and content answers the original
`origin, stream, seq` with `replayed: true`; same key, other content is 422 `idempotency.mismatch`. Every row an emit inserts
has a UUIDv5 id derived from its key. When the gateway is down an interactive caller answers 503 `emit.unavailable`; a
queued emission waits in the caller's `emit_queue`.

## Open wire details (ADR-0002 A2.8, left to the implementers; to be added here by the change that builds them)
The `stale_seals` list beside `placeholders`, the `unbound` list in `hello` and the `chain_conflict` refusal reason are rules
(A2.8 items 1 and 2) without a settled field name; the OpenAPI document does not carry them yet. KR1 and PH1 to PH3 are
the checks.

## Hold codes, verdicts
`pending`, `held_manager`, `held_support` only (see Verdicts above). Flags and reasons exist behind member-token admin
endpoints (`listExceptions`, `listQuarantine`) and never reach a device.

## Several document numbers in one op; mixed field policies
- **One op may allocate more than one legal document number** when its intent inserts more than one numbered document, for
  example `bill.rebill` = a credit note number (series of type credit_note) and a new bill number (series of type tax_invoice
  or bill_of_supply), allocated in the same local transaction. Each number sits in the `doc` of its own inserted row
  (the registry marks the entity's `doc_number` field, `numbering: allocated`, and lists every document type in `documents`).
  The op body's single `doc` member of OpBody carries the first; the others are read from the mutated rows' `doc_number`
  fields by the gateway and the register. An op never takes a number twice from one series.
- **Entities with mixed per-field policies are valid** (`check`, `order_line` and other entities whose `policy` is `mixed`):
  each field states its own policy (`immutable`, `lww`, `lww_review`, `delta`, `rank`) and the engine applies it per field
  group; a `set` mutation names only fields of `lww` or `lww_review` policy, an `insert` sets immutable and initial values.
  Conflict resolution is per field group, never per row.
