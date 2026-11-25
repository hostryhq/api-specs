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
- Canonical form (JCS) is RFC 8785 for the integer-only subset: object keys sorted by UTF-16 code unit order, no whitespace,
  strings escaped minimally (only `"`, `\`, the short forms `\b \f \n \r \t`, and other code points below U+0020 as lower-case
  `\u00xx`; everything else, including non-ASCII and `/`, is written as UTF-8 unescaped), `-0` is `0`, integers only within
  +-(2^53-1). Fractions and exponents are refused (money is paise). The same form is used for the op body, for the values inside
  personal-data commitments and for the rows of a projection digest; the `canonical` vectors in `sync/conformance/v1.json` are the
  check, and `internal/canon` in this repository is the reference.
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
Flags, reasons and attribution labels exist only behind member-token admin endpoints. `pending` also covers an op that cites an approval
whose `approval.grant` has not arrived (Approval citation below).

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
- **Subscribing (go-common `bus`, 9d9cf03).** `sync.op` is the one two-segment event type; the namespace is appended at publish time.
  The registry file `events/sync/op.v1.yaml` carries `x-subscribers-by-namespace` (namespace to the services that own or read an
  entity of it); the subject set of a service's consumer is `evt.sync.op.<namespace>.v1` for exactly the namespaces that list it, and
  every service named there must also be in `x-subscribers`. The key is refused on any other type. `make lint-intents` checks the map
  against the entity and intent registries; regenerate it when an intent or entity changes.
- Envelope `key` = `<stream>|<origin>`, `key_seq` = `seq`, `outlet_id` set for an outlet stream. **A consumer does not wait
  for gaps and does not need order**: `seq` is sparse for a service (it sees only its namespaces) and the apply engine gives
  the same rows for any arrival order (a row whose parent is missing is parked, ADR-0002 S11).
- An op is published when it becomes applicable: at acceptance, or at release from quarantine. A quarantined op is never
  published with its body. `sync.quarantine.recorded` (series code, number and document type, no content) and
  `sync.op.flagged` (identity and coarse code) are id-only types.
- `pii` travels in the event (a stated exception to ADR-0011 B6), in the shape of Personal data below: entity, row id, field,
  value, **and each field's salt next to its value** (key `~s:<field>`, base64url; O2-12), only fields that verified against
  `body.pii_c`. The gateway does not strip salts, so the owning service can verify `pii_c = SHA-256(salt || JCS(value))` itself.
  A consumer stores `pii` fields (values and salts) only for entities it owns, in an erasable side table, and never for a replica
  (`replicated_to`, ADR-0014 A2.4). `sync.pii.erased` (ids only) tells each owner to erase values and salts.

## Cloud-origin emit (ADR-0014 A2.2)
Operation `emitOps` (`POST /internal/v1/emit`) is the only way a service writes data to devices. **Tenant (O2-11):** the service
token used for it carries a tenant claim (the caller mints one per tenant); the body's `tenant_id` must equal it, else 403
`emit.tenant_mismatch`, and a token without a tenant is 401. The gateway alone stamps
`origin = cloud-<epoch>`, `seq`, `ph`, `hlc` and seals the batch; a caller never chooses them. It checks that the caller owns
the intent, the intent is cloud-origin, every mutation is of an entity and kind the intent lists, the stream belongs to the
tenant and the size limit. Idempotency is `(tenant_id, caller, key)` per op: same key and content answers the original
`origin, stream, seq` with `replayed: true`; same key, other content is 422 `idempotency.mismatch`. Every row an emit inserts
has a UUIDv5 id derived from its key. When the gateway is down an interactive caller answers 503 `emit.unavailable`; a
queued emission waits in the caller's `emit_queue`.

## Wire fields of ADR-0002 A2.8 (as both engines implement them)
KR1 and PH1 to PH3 are the checks. All fields are additive and optional; a node that sends none behaves as before.
| Where | Field | Shape | Meaning |
|---|---|---|---|
| `HelloRequest` | `unbound` | `[{origin, stream, seq}]` | Slots the node took by hash with no binding yet. Only the cloud answers; listed at every direct cloud hello. |
| `HelloRequest` | `chain_conflicts` | `[{origin, stream, seq, held, seen?}]` | Chain conflicts the node recorded and has not reported: `held` is the hash the node holds, `seen` the hash that contradicted it. |
| `HelloResponse` | `unbound_h` | `[{origin, stream, seq, h}]` | The cloud's own hash for each slot named in `unbound` that it holds. |
| `PullRequest` | `stale_seals` | `[{origin, stream, seq}]` | Stored cloud-origin seals under an op-signing key the caller no longer accepts. |
| `PullResponse` | `seal_refresh` | `[Seal]` | The current seal for each `stale_seals` entry. |
| `Refusal.reason` | `chain_conflict` | enum value | A body or link contradicts what the node holds or what a seal states. Beside `fork_evidence_kept`. |

## Proof fields of an op body (ADR-0005 A3.1)
All inside the sealed body. `pack_v` is a JSON integer >= 1 on every device-origin op (cloud-origin ops carry none). `proof` and
`pin_v` (integer >= 1) appear together and only on `session.open` of a `pin` session (the actor's `pin_v`) and on `approval.grant`
(the approver's `pin_v`); a `proof` on any other intent is ignored and never sent to identity. On `session.open`, `at` is the
opening time the proof binds. The gateway asks identity once per proof (`verifyProof`, `Idempotency-Key` from `(origin, stream, seq)`)
and stores the verdict per `(tenant, origin, sid)`; identity unreachable is `pending`, never `valid`.

## Proof messages (ADR-0005 sections 7 and 8, A3.1; vectors `approval_proof`, `action_hash`)
The proof is `base64url-nopad(HMAC-SHA256(proof key, message))`, the message the fields below joined by `|`. Times are UTC with exactly three
millisecond digits (`2026-11-24T13:05:11.120Z`). `target` and `reason` are free text and are quoted with Go's `strconv.Quote`
(double quotes; `\"` `\\` `\a \b \f \n \r \t \v`; other control characters and invalid UTF-8 as `\xNN`; non-printable code points as `\uNNNN`;
printable Unicode, `|` and `/` unescaped) so a separator inside them cannot move a field boundary. `svc-identity` builds and checks these
messages (`SessionProofMessage`, `ApprovalProofMessageBound`); `client-core` must match them byte for byte.
- **Session proof:** `session|<sid>|<device id>|<member id>|<pack_v>|<pin_v>|<opened at>`.
- **Approval proof** (the approver's, over the record of `approval.grant`): `approval|<action hash>|<device id>|<approver member id>|<pack_v>|<pin_v>|<approval id>|<permission>|<quoted target>|<requester id>|<approved at>|<quoted reason>`;
  `reason` is the empty quoted string `""` when the record has none. `approved at` is the op's `at`.
- **Action hash:** `sha256:` plus the lower-case hex SHA-256 of the JCS of the object `{intent: <intent name>, <name>: <value> ...}` with one
  member for each name the intent lists in `proof.binds`. A value is read from the first mutation of the op that sets a field of that
  name (integers stay integers, ids stay strings). Because `intent` is in the hash, the proof binds the intent as well as the permission
  and target. A bound name the op does not set fails the check as `mismatch`.

## Approval citation (ADR-0014 A3.3; ADR-0005 section 8)
An op of an intent with `override: true` whose actor lacks the permission cites an approval: body field `approval` = the approval id. The
`approval.grant` op (the approver's own, same device, same `sid` or a session the same origin recorded) carries the record above. The
gateway keeps one row per `(tenant, origin, approval id)` with the record and the `verifyProof` verdict (ADR-0005 A3.1 item 3).
Question 6 (permission) for an op that cites an approval is answered **by the approver** when all hold: the intent is `override: true`;
the approval verdict is `valid`; same origin and same `sid` as the `approval.grant` op; the record's `intent` and `permission` are the op's;
`requester` = the op's `actor`, and differs from the approver unless the actor holds the permission (own sensitive action); the approver held
the permission in the op's `pack_v`; the action hash recomputed from the op and the `target` row match; the op's `at` is 0 to 120 seconds
after the approval's; no other op cites the approval (the lowest `hlc` keeps it). The op is then **`accepted` with no flag**, attribution
`verified`, shown as "approved by". The actor's own lack of the permission is never a `permission_flag` on this path.
- "Then current grants" is asked of the approver: removed since, a trading fact is accepted and flagged with the removal date; a
  configuration change is voided.
- **Not yet known.** The `approval.grant` op has not arrived (it is in the outlet stream, the action may be in the brand stream) or identity is
  unreachable: the verdict is **`pending`**, judged again; never `permission_flag`.
- **Failure.** Any condition false: `unverified`, flag **`approval_flag`** with a `reason`: `proof_invalid`, `mismatch` (intent, permission,
  requester, target or action hash differ), `reused` (another op cites it), `expired` (outside 120 s), `approver_not_permitted`, `self`
  (requester is the approver and lacks the permission). A trading fact is accepted at high severity; a configuration change is voided.
  **`permission_flag` remains only** for an actor without the permission who cites no approval, or an intent that is not `override: true`.
- **Hub.** Its structural check is the same without the proof: an approval is cited, the approver is in the pack with the permission and
  is not the requester.

## Device credential (ADR-0005 A3.2 row 1, ADR-0014 A3.4)
`Credential` = `device_id`, `tenant_id`, `outlet_id`, **`brand_id`**, `kind` (`pos`, `waiter`, `personal`, `kds`, `hub`), `kid`, `pub`, `not_after`, and
`recovers` for a key-loss adopter; identity signs it (`hostry-cred-v1`). **`brand_id` is always present**: identity reads it from
tenancy when the device is activated, stores it on the device row and signs it; nothing re-asks. A hub and LAN peers therefore judge
whether a device may write a `brand:<id>` stream offline from the credential alone. The offline pack's `device` object carries the
same `brand_id` and the device's own credential `kid`. An outlet never changes brand (tenancy answers 409 `outlet_brand_fixed`).

## Drain statement (ADR-0005 A3.3)
Domain tag `hostry-drain-v1`. Object `{origin, streams: [{stream, seq, h}], series: [{series_id, code, fy, last_number}], by, rec?, kid,
at, sig}`; `sig` = ES256 over `"hostry-drain-v1\n"` + the canonical JSON (RFC 8785) of the object without `sig`. `streams` lists every
stream in which the device's log holds an own-origin op with its head; `series` every series in its pack in the fields of a
`series_close` record (0 when never used). Ordinary drain: `by` = `origin`, signed with the revoked device's key. Key loss: `by` = the
adopting device, `rec` = the recovery id, signed with the new key. It travels as `PushRequest.drain_statement` on the last, empty
`quarantine-upload`, once the answered `vector` covers every own head. The gateway reports `recordDeviceDrained` only when the device is
revoked, the signature verifies against its credential, it holds every `seq` up to each stated head with a matching `h`, holds no op
of that origin in an unstated stream or above a stated head, and its register holds no number above a stated `last_number`; any mismatch
is stored as fork evidence and reports nothing.

**`statement_hash`** (the field of the wipe order, `WipeOrder.statement_hash`) = lower-case hex SHA-256 of the UTF-8 bytes of the JCS
(RFC 8785, the integer-only subset of Framing and hashing) of the **whole statement object including `sig`**; `rec` is a member only
when present (an ordinary drain has none, and an absent member is omitted, never `null`). The signed message is the JCS of the same
object **without** `sig`, so the hash binds the signature too and two statements that differ in any byte of `sig` never share a hash.
`streams` and `series` keep the order the device wrote (arrays are not sorted by JCS; the device sorts `streams` by `stream` and `series`
by `series_id` before signing, so one log gives one statement). A verifier hashes the JCS it recomputes from the parsed object, never the
received text, so insignificant whitespace or key order on the wire cannot change the hash. The `drain_statement` vectors in
`sync/conformance/v1.json` give, per case, the statement, the exact signed message, the JCS with `sig`, the hash and whether the
signature verifies (one case is a statement whose field changed after signing: signature invalid, a different hash).

## Attribution of device-session ops (ADR-0005 section 7; soak finding F6)
A device session (`session.open` with session type `device`: a KDS, no member, no PIN, no proof) has an actor of its own, so its ops
are attributed and never held as `actor_unknown`.
- **`actor`** on every op of a `device` session is the literal text `device:<device id>`, and `<device id>` equals the op's `origin`.
  `sid` is the id of that session. A free text such as `device-kds`, a `device:` naming another device, or a plain member id on a
  device session is `actor_unknown` (held, never published). The implicit `actor` column of every row holds the same text, so reports
  show "device Kitchen KDS" where a member would be.
- **The gateway checks** that the `session.open` of `sid` was recorded by the same origin with session type `device`, that the device
  is in the pack with a kind its intent lists (`device_kinds`), and judges the intent's permission against the **device role template
  of that kind** (the KDS role holds `kds.bump` and `menu.availability.set`; `x-provisional` until the ADR-0005 role templates say
  so). No member permission is consulted, no approval is possible and no action proof exists in a device session.
- **Intents that allow a device session** are exactly those that list `device` in `sessions` in `sync/intents`: `session.open`,
  `kds.status` (bump, forward-only rank), `kds.recall`, `menu.availability.set` and `series.close`. Every other intent needs a member
  (`pin` or `strong`). An intent with `proof.kind: action` never lists `device` (`make lint-intents` refuses it); neither may one with an `override`
  or a `sensitive` permission, which need a member.

## Manual-book entries and the foreign-series rule (ADR-0003 A1.5, ADR-0014 A1.6 item 4; soak finding F7)
A legal number whose series code the issuing device does not hold is a `foreign_series` hold (ADR-0003 A1.5). A **paper-book number
typed by `bill.manual_entry`** (numbering `typed`) is not foreign when its series code belongs to a **registered, active `manual_book`
series** of the organisation's tax registration that lists the op's outlet:
- The gateway's register knows the book from tenancy: it asks `listOutletManualBookSeries` (`GET /internal/v1/outlets/{outlet_id}/manual-book-series`,
  cached 60 seconds, dropped on `tenancy.manual_book.registered`) and carries every book as an **entry-only series** in its register,
  keyed `(series code, FY)`, kind `manual_book`. Identity puts the same books in the offline pack (`manual_books`, entries of
  `{code, tax_registration_id}`), so a device refuses an unregistered code before it records anything.
- **Any** billing device of a listed outlet may type a page; no origin owns the series. The op is accepted and published, and the
  register stores the typed number under the book. The bill id is the UUIDv5 of (series, FY, number), so the same page typed on two
  devices (or twice) is one row and no `duplicate_document`; a different bill id on the same typed number is `duplicate_document`
  (flagged, both kept).
- **No gap detection** runs on a manual book (a page is typed when it is found; numbers arrive in any order) and a manual book
  never takes part in `series.close` reconciliation or a drain statement. A page of a **closed** book is accepted and flagged
  `after_closure`.
- A code that is in no registered book of the outlet is still `foreign_series`, held for the manager as before. A book registered
  after the page was typed does not release the hold by itself; the manager releases it (`releaseQuarantine`).
- A device-allocated series (`numbering: allocated`) is unchanged: only its own device may use it.

## Day close cutoff (ADR-0014 A1.1 item 4; soak finding F8)
A closed day carries **two** unrelated things that were both once called a cutoff, and the contract now names them apart.
- **`cutoff_at`** (RFC 3339 UTC timestamp, field of `day_close` and of `DayClose`) is the instant the device closed the day by its
  clock as confirmed to the cloud (`closed_at` of the Z). It is the **late-bill rule's** only input: a bill (or credit note) of that
  business date whose finalisation time (`at` of its op, UTC) is **after** `cutoff_at` of the canonical close is a **late
  document** (`late: true`, a revision of the Z, cause `late_device` when it came from a device that was offline). Comparison is on
  instants, never on dates or on IST calendar days.
- **`cutoff`** (canonical JSON text of a version vector `{origin: seq}`) is unchanged: what the closing device held, used only to say
  which ops the printed Z covers. It is **never** parsed as a time. A reader that needs "late" reads `cutoff_at`.
If two devices close the same date, the canonical close is the lowest stamp and its `cutoff_at` decides lateness.

## Hold codes, verdicts
`pending`, `held_manager`, `held_support` only (see Verdicts above). Flags and reasons exist behind member-token admin
endpoints (`listExceptions`, `listQuarantine`) and never reach a device.

## Several document numbers in one op; mixed field policies
- **One op may allocate more than one legal document number** when its intent inserts more than one numbered document, for
  example `bill.rebill` = a credit note number (series of type credit_note) and a new bill number (series of type tax_invoice
  or bill_of_supply), allocated in the same local transaction. Each number sits in the `doc_number` field of its own inserted row
  (the registry marks the entity's `doc_number` field, `numbering: allocated`, and lists every document type in `documents`).
  **The op body carries them in `docs` (O2-7)**, an array of `{type, number}` in the order allocated; `doc` is the first of them
  and stays for readers that know one. The gateway and the series register read `docs` when present, else `doc`. An op never
  takes a number twice from one series.
- **Entities with mixed per-field policies are valid** (`check`, `order_line` and other entities whose `policy` is `mixed`):
  each field states its own policy (`immutable`, `lww`, `lww_review`, `delta`, `rank`) and the engine applies it per field
  group; a `set` mutation names only fields of `lww` or `lww_review` policy, an `insert` sets immutable and initial values.
  Conflict resolution is per field group, never per row.

## Personal data beside an op (security ruling SR-2, O2-8, O2-12; ADR-0014 A3.1, A3.2)
Customer data (name, phone, GSTIN) never sits in the hashed body in the clear, and never as a plain hash (a phone number could be
guessed back from one). It travels in `Item.pii` outside the hash so that erasure never touches the chain.
- **Shape.** `pii` = entity name, then row id, then field name, then value (string, boolean or integer), for the entity fields
  marked `pii: true`. At most 16384 bytes of canonical JSON. In Phase 2 the fields are `customer_name`, `customer_phone` and
  `customer_gstin` on `check`, and `customer_name` and `customer_gstin` on `bill` and `credit_note`.
- **Commitments (one per field, mandatory).** The sealed body carries `pii_c` with the same nesting, each field `lower-case hex SHA-256(salt || JCS(value))`.
  `salt` is 16 fresh random bytes per field; `JCS(value)` is the canonical JSON text of the value (a string is quoted and
  escaped, a boolean is `true`/`false`, an integer is its digits), so a string and a number can never commit to the same text.
  A hash over the whole map is not allowed: placement and erasure are per field. Every node holds the commitments, a `kds` included,
  because they are in the body. Vectors `pii_commit` in `sync/conformance/v1.json`.
- **Salts on the wire.** Each field's salt travels in the same `pii` object under the key `~s:<field>` (base64url, no padding).
  A field name starting with `~s:` is reserved. The gateway, hubs and the owning services keep value and salt together.
- **Who receives `pii` (A3.1 item 1).** Same-outlet devices whose credential kind is `pos`, `waiter`, `personal` (bound to the
  outlet) or `hub`, and the cloud. A node answering a **pull or snapshot** to a puller whose credential kind is **`kds`** removes the
  whole `pii` object (and the `~s:` salts with it); the commitments in the body stay. This is one rule on the envelope, so the hub
  stays domain-agnostic (ADR-0002 S8); there is no per-field `pii_to` list in Phase 2 (named extension for Phase 5). A field a
  kitchen screen must show (token, table) is not personal data and is never declared `pii`. Vectors `pii_placement`.
- **Path.** A push to any upstream, a hub or the cloud, carries `pii` with each value and its salt. A hub stores it in its encrypted op
  store (ADR-0002 S8) and relays it both ways. Pull and snapshot carry it to the kinds above, minus erased fields. A snapshot row
  carries `pii_c` (field to commitment) always, and `pii` (values and salts) only where a pull would.
- **Verification (receiver rules).** Every node of the kinds above that ingests `pii` recomputes each commitment; a field with no
  commitment, no salt or a value that does not match is dropped (never stored, never published), refused, alerted and the op is
  marked `pii_dropped`. A commitment with no value, not named by an erasure op, is **`pii_incomplete`**: the row applies, the
  field shows as pending and is fetched at the next contact with any upstream. A `kds` expects no value and fetches none. A
  commitment with no value is otherwise normal (erased, or not sent). The gateway publishes the verified values *with* their salts
  (op event above), so an owning service can verify again.
- **Reprint and credit note on another device (A3.1 item 6).** They use the local values and work with no internet. If a buyer
  field is `pii_incomplete` the device fetches it when an upstream is reachable and otherwise refuses with
  `customer_details_pending`; a B2B duplicate is never printed with the buyer block blank. An erased field prints as "erased".
- **Erasure (unchanged, and it wins for ever).** The cloud-origin op of intent `sync.pii.erase` with one mutation of the record `pii_erase` (id `stream|origin|seq`
  of the target op, fields `origin`, `stream`, `seq`) reaches every device and hub in the stream and removes the values AND the
  salts of the target op from every node's rows, op log, op copies, caches, spool and exports, and makes the node discard any
  later arrival of that op's `pii` on receipt. The commitments stay in the sealed body
  and cannot be reopened without the salt. The gateway writes the op and `sync.pii.erased` (ids only) in one transaction; erasing
  twice answers the first erasure op. **Acknowledgement:** the next direct cloud `hello` of a node carries `pii_erased` (array of
  refs of the target ops); the gateway records it per node. A node that reaches only a hub keeps the list until its next direct
  cloud hello. GST retention (72 months) means erasure is field-level; the document itself stays. **How it is requested:** the owning
  services call `erasePii` (`POST /internal/v1/pii/erase`, service token with the tenant claim, permission `sync.pii.erase`, callers
  `billing` and `orders`); the gateway writes the op and `sync.pii.erased` in one transaction, as above. Every `pii: true` field of a
  bill, credit note or check is covered, including `customer_gstin`.

## Control records
Records are mutations whose `e` is not a synced entity. They are listed by the intents that carry them (`records:` in
`sync/intents`) and have no entity schema; the shapes are:
| Record | Intent | Origin | `id` | `f` |
|---|---|---|---|---|
| `approval` | `approval.grant` | device | the approval id (client UUIDv7) | `permission`, `intent` (the intent the approval is for, one with `override: true`), `target` (`<entity>:<row id>` of the row the action concerns), `action_hash`, `requester` (member id), `reason` (optional, at most 200 characters); the approver is the op's `actor`, the time its `at` |
| `sync_void` | `sync.void` | cloud | `stream|origin|seq` of the voided op | `origin`, `stream`, `seq`, `reason` = `refused` |
| `pii_erase` | `sync.pii.erase` | cloud only | `stream|origin|seq` of the target op | `origin`, `stream`, `seq` |
| `series_close` | `series.close` | device | the series id | `code` (3-character series code), `fy` (four digits), `last_number` (integer >= 0, the last running number the device allocated from the series; 0 when it never allocated) |
A node ignores a record it does not know (older clients, ADR-0002 S13). `series_close` is statement-once per (device, series): a
replay is ignored and a second statement with another `last_number` is refused and alerted. Billing reads `series_close` from the
`sync.op.series` event; `go-common/sync.ParseOp` exposes it as a control record.

## Projection digest, algorithm `sha256-canon-v1`
The digests of `getOrdersProjectionDigest` and `getBillingProjectionDigest` equal what a device computes from its local entities, so
that convergence can be tested (ADR-0014 T2, T9, T11). The **canonical row form**:
1. **Rows.** The rows of the entities the service owns that belong to the business day: the entity has a `business_date` equal to
   it, or no `business_date` and a `day_parent` (a required id field of the entity file) whose row belongs to the day, **followed
   until a row with `business_date` is reached** (line, then order, then date; ADR-0005 A3.5). `order_line_cancel` names
   `order_line_id`, so void, cancel and grace cancel resolve the same way and `kot_id` no longer decides the day. Entities declared
   `outside_digest` and rows whose parent has not arrived (on both sides) are left out. Tombstoned rows and replicas of another
   owner's entities are left out.
2. **Row text (ADR-0014 A3.2).** The JCS (RFC 8785, integers only) of an object holding `id`, every **non-`pii`** field of the entity
   schema the row has set (absent and null fields omitted) and, for each `pii: true` field the row holds a commitment for, the member
   `~c:<field>` whose value is that field's **commitment** (lower-case hex, from `body.pii_c`), nothing implicit (no `tenant_id`,
   `origin`, `actor`, `hlc`). **Never a `pii` value or salt.** The commitment is the one of the write that wins the field under its own
   merge rule, so two nodes that hold different winners for `customer_name` differ in the hash. A `pii` field with no commitment (never
   set) has no member. Hence the text and every hash over it are equal on the origin, its peers, a `kds`, the hub and the cloud, and do
   not change when a field is erased. Vectors `digest_row`.
3. **Entity digest.** `hash` = lower-case hex SHA-256 over the row texts in ascending `id` order (byte order), each followed by a
   line feed; `row_count` is the number of rows. Only entities with at least one row are listed, in ascending name order.
4. **State hash.** `state_hash` = lower-case hex SHA-256 over, for each listed entity in ascending name order, the text
   `<entity>\n<row_count>\n<hash>\n`.
**One rule for every convergence hash.** The device state hash, `acceptedStateHash` and this projection digest all cover the non-`pii`
fields and each `pii` field's commitment, never a value. `examples/digests/*.json` hold the rows of the digest example worlds (with
the commitments of their `pii` fields, no values) and `make lint-digests` recomputes the OpenAPI examples from them.

## Events published by the gateway
The sync gateway (service `sync`) publishes: `sync.op.<namespace>` (op applicable), `sync.op.flagged` (an op flagged at acceptance or
afterwards; identity and coarse code only), `sync.quarantine.recorded` (a slot held; series code, number and document type, no
content) and `sync.pii.erased` (ids only). Each is written in the transaction of the state change that causes it. It does **not**
publish `billing.series.reconciled`: that is billing's event (O2-10), published after billing has consumed the device's
`series.close` op (or identity's `identity.device.drained`) and holds every number up to `last_number`.

## Quarantine decisions
`releaseQuarantine` and `discardQuarantine` require a `reason` (1 to 200 characters); a member cannot decide a hold on their own op.
`confirmSyncQuarantine` (permission `sync.quarantine.confirm`, support token in act mode only) is Hostry support's confirmation of the
cause of a chain-broken, foreign-series or fork hold, bound to the held op by its hash `h`. It releases nothing; the organisation's
manager releases afterwards. The held list (`listQuarantine`) needs `sync.quarantine.read`, which a support session may use in view mode.
