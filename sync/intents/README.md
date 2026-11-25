# Sync intent registry

One YAML file per owning group (`orders`, `billing`, `catalog`, `control`, `cloud`). From these files are generated the client's `can()` table,
the gateway check (ADR-0002 S11) and the hub structural check (S8); each service generates its bus subscriptions from the entities an intent
touches (ADR-0014 R1; subscription `sync.op.<namespace>`, namespace = the text before the first dot). `make lint-intents`
(`cmd/validate-intents`) is the CI gate; it runs inside `make lint`.

An **intent** names what an op means. The mutations are applied by the generic engine; the intent carries authorisation and audit meaning.
Actions that need a `strong_only` permission have **no intent**: they are online API calls (for example `setDiscountLimit`,
`setNumberingMode`, `setOutletTaxProfile`, menu tax class, CSV import, role and member administration) and never travel as ops.

## Keys

| Key | Meaning |
|---|---|
| `intent`, `intent_v` | Name `<namespace>.<action>[.<qualifier>]` and version. A change of meaning is a new `intent_v`; the gateway keeps an upcaster for every `intent_v` a released client could emit (ADR-0002 S13). |
| `class` | `trading` (facts: never rejected for a permission reason, flagged instead), `config` (judged against current grants; voided on failure; in a `pin` session accepted and listed as "configuration changed on a shared device"), `control` (session, approval, device). ADR-0002 S11. |
| `owner` | The service that owns the intent's meaning and its upcasters: an owner of one of the touched entities, `identity` or `gateway` when no entity is touched, `gateway` for a generic cloud emit. Subscribers are the owners of every touched entity. |
| `permission` | Catalogue key (`common/permissions.yaml`), tenant realm, never `strong_only`. `null` only for `control` or cloud-origin intents, with `permission_reason`. |
| `authorised_online_by` | Cloud-origin intents only: the online permissions that authorised the emit before it was queued. |
| `proof.kind` | `session` (the stamped session proof, ADR-0005 section 7 question 4) or `action` (the action proof of section 8; own PIN re-entry in a `pin` session, nothing extra in a strong session). `proof.binds` names the fields the action hash covers. An action proof needs a `sensitive` permission and a member, so never a `device` session. |
| `override` | A manager who holds the permission can approve it on the same device (ADR-0005 section 8). Needs `proof.kind: action`. |
| `allowance` | Flag A permissions (ADR-0014 A1.5 item 6): own intent, verifies without an approval record, counted per member per shift against `limit_setting` (an outlet setting), re-checked by the owning service as a detector (`checked_by`). `above_allowance` says what is used beyond the limit: another intent (`use_intent`) or an approval for a permission (`approval_permission`). |
| `sessions` | Session types allowed to record it: `pin`, `strong`, `device` (KDS and hub roles; no member). Empty for cloud origin. |
| `device_kinds` | `pos`, `waiter`, `kds`, `personal`, or `cloud` alone (the gateway emit). A `hub` never originates intents; it relays. |
| `streams` | Streams the intent may be recorded on (ADR-0002 S3). One op touches entities of **one** stream; every touched entity's stream must be listed. |
| `numbering`, `documents` | `allocated` (number taken from the device series in the same local transaction), `typed` (entry-only paper-book series) or `none`; the document types it consumes. Must agree with the touched entities' `doc_number` fields. |
| `entities` | Map entity name to the mutation kinds (`insert`, `set`, `delta`, `rank`, `del`, `undel`) the intent may use. Kinds must agree with the entity's field policies and tombstone flag. A cloud-origin-only entity appears only under a cloud intent. |
| `records` | Protocol records that are not synced entities: `session`, `approval`, `series_activation`, `series_close`, `clock_confirmation`, `sync_void`, `pii_erase` (shapes: sync/protocol-v1.md, Control records). |
| `pii_fields` | Touched fields that travel in the op's `pii` object, outside the hash. |
| `idempotency` | What a replay does. Offline clients retry and sync resumes, so every intent states it. |
| `x-provisional` | A choice made by this registry that needs a ruling; listed below. |

## Rules enforced by the lint

Every intent has a class, a catalogue permission (or a stated reason for none), an idempotency rule and a description. An intent never names a
`strong_only` permission. Every entity exists; each entity's `written_by_intents` names only intents that exist and list that entity; every entity
is written by at least one intent. A guarded (money or tax) entity is never changed by a device `config` intent. Names are unique across files.

## svc-sync PoC names

`svc-sync/syncproto/intents.go` is the PoC subset (permission strings are the PoC's own and are not catalogue keys). Mapping to this registry:
`order.line.add`, `order.edit` to `order.line.add` / `order.line.edit` (`order.edit`); `kot.send` (`order.edit`); `kds.status`, `kds.new`, `kds.ready`, `kds.late` to
`kds.status` (`kds.bump`, one forward-only rank); `bill.finalize` (`bill.finalize`); `pay`, `payment.record` to `payment.record`; `refund` to `payment.refund`;
`creditnote.issue`, `credit_note.issue` to `creditnote.issue` (`bill.credit_note.create`, action proof, override); `menu.item.edit`, `menu.add`, `menu.rename`,
`menu.del`, `menu.undel` to `menu.item.edit` / `menu.item.archive` (`menu.manage`); `menu.price.set`, `menu.price` to `menu.price.set` (`menu.price.edit`);
`stock.*` have no Phase 2 intent (stock is Phase 4 and 8); `conflict.confirm` is not in the restaurant registry (exceptions are resolved online in Phase 2);
`approval.grant`, `session.open` and `series.activate` keep their names; `sync.void` keeps its name (cloud-origin); `cloud.emit` is retired for one named cloud-origin intent per online action (`menu.tax_class.set`, `tax.rule_set.publish`, `settings.tax_profile.set`, `settings.numbering.set`, `settings.discount_limit.set`, `day.revision.record`; ADR-0014 A2.3); `series.close` is the device statement of a closed series (ADR-0014 A2.5); `bill.reprint` is an audit-only trading intent.

## Provisional choices

| Choice | Intent | Needs |
|---|---|---|
| Catalogue keys `series.activate` and `device.clock.confirm` added (the spec and ADR-0005 section 8 name the actions; the catalogue lacked them) | `series.activate`, `device.clock.confirm` | `security-reviewer`; ADR-0005 owner |
| Above the re-bill allowance a manager's approval is for `bill.credit_note.create` | `bill.rebill` | `security-reviewer` |
| Internal closure and open item use `bill.line.comp` beyond their allowance; their limit setting keys are new | `check.close_internal`, `menu.open_item` | product |
| `menu.price.outlet_set` (per-outlet override, Could) replaces `menu.price.set` in `item_outlet.written_by_intents` because an op has one stream | `menu.price.outlet_set` | product |
| `kds.status` and `menu.availability.set` allow a `device` session; the KDS role is assumed to hold `kds.bump` and `menu.availability.set` | `kds.status`, `kds.recall`, `menu.availability.set` | ADR-0005 role templates |
| `kot.print.ack` and `seating.close` use `order.edit`; they are device-side facts with no permission of their own in the spec | those two | product |

## Not in the registry

- `bill.reprint` and the reprint log (reports 14, `bill.reprint` permission): no synced entity records a bill reprint, so there is nothing for an op to mutate. Needs an entity (for example `bill_reprint`) or a statement that the log is device-local only.
- `exceptions.resolve`, `member.disable_local`: resolution is an online call in Phase 2; `member.disable_local` is off until the ADR-0005 amendment (O2-2).
- Strong-only online actions listed above; `tender` collection by gateway (Phase 3).
