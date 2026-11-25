# Phase 2 acceptance-criteria coverage

Maps the `[API]` and `[OFFLINE]` criteria of `docs/product/restaurant-mvp-spec.md` (section 8) and `docs/product/admin-a1-spec.md`
(section 8) to the contract that expresses them. Owners: `C` catalog, `O` orders, `B` billing, `T` tenancy, `E` entities
(`entities/restaurant`), `X` tax (`tax/`), `Ev` events. A criterion is "expressed" when the contract states inputs, outputs, errors and,
where it can, the rule. Most restaurant criteria are device behaviour (the ordering, billing and kitchen logic runs in `client-core`
and `app-restaurant`, ADR-0014 R1, R4); for those the contract is the **entity schema** (what is stored, its conflict policy) and the
**tax vectors**, and the criterion is proven by the domain unit tests against those, not by an HTTP call. Rules about storage, logs,
database roles and isolation suites are implementation tests and are listed as gaps at the end.

## Restaurant, section 8

| AC | Where it is expressed | Note |
|---|---|---|
| 3 modifier bounds | `E modifier_group` (min_select, max_select), `C ModifierGroup` | Enforced on the device |
| 4 tax class needs a strong session | `C setItemTaxClass`, `setCategoryTaxClass` (`x-step-up`, 403 `strong_session_required`); `E item.tax_class`, `category.default_tax_class` | Online API, never a pin-session op |
| 5 price edit with PIN re-entry, listed for owner | `E price_entry.price_paise` (`lww_review`); `C listCatalogExceptions` (`config_changed_shared_device`, `price_conflict`) | Action proof is an intent property (intent registry) |
| 6 concurrent price edit | `E price_entry` (`lww_review`, group `price`), detector `concurrent price edit`; `C listCatalogExceptions` | |
| 7 open lines keep old price | `E order_line` (snapshot fields immutable) | |
| 10, 13, 14 import all-or-none, validation, archive rule | `C createMenuImport` (preview with `ImportRowError`), `commitMenuImport` (422 `import_has_errors`); `E category` detector | |
| 15 to 25, 34, 35 calculation figures | `X vectors.v1.json` TV-055 to TV-064 carry the figures the criteria state (`spec_expect`); TV-001 to TV-054 cover rounding, groups, discounts, charges, inclusive, regimes, credit notes | **Discrepancy:** AC 17 and 18 state totals 28350 and 34650, the pre-round totals; with round-off on (the reference bills) they are 28400 and 34700. Pinned as such in TV-057, TV-058 (CA) |
| 26 two implementations agree | `X tax/README.md`, `reference/` (`go test ./tax/...`); `B validateTaxRuleSet` runs the vectors | TypeScript side is client-core's test |
| 27 rule set in force on the invoice date | `B listTaxRuleSets?in_force_on`; `E tax_rule_set.effective_date`, `bill.ruleset_id`, `bill.invoice_date` | |
| 29, 30 strong settings, FSSAI | `B setOutletTaxProfile` (`x-step-up`, pattern 14 digits), `setNumberingMode`, `setDiscountLimit` | |
| 31 to 33 GSTIN check, regime, unverified registration | `E check.customer_gstin`, `bill.doc_type`; `B Bill.doc_type`; detector `document type does not match the regime` | Check character is validated by the service/client (`Gstin` pattern only here) |
| 36 SAC | `E tax_rule.sac`, `bill_line.hsn_sac`; `X rule-set.schema.yaml` | Not shipped until the CA advises |
| 41, 44 no stored table status, counter has no seating | `E dining_table` (no status field), `order.seating_id` optional | |
| 49 cancel wastage flag and report | `E order_line_cancel.wastage`; `O getCancellationReport`, `CancellationRow.wastage` | |
| 54, 55, 120, 112 immutable bill, no edit | `E bill` (all fields `immutable`, `guarded`); no update or delete operation on `B` | Contract has none by construction |
| 64, 16 shares | `E payment` (several rows per bill); `B Payment`, detector `payments exceed the bill total` | Rule is device-side |
| 66 whole check cancel | `E check_cancel` (approval_id, presented) | |
| 69, 210 append facts with actor, device, time | `E` README implicit columns (`origin`, `actor`, `hlc`) | |
| 71, 72 two KOTs, KOT content | `E kot`, `kot_line` | Rendering is client-core |
| 77, 86 rank policy, kds intents | `E kot_line.status` (`rank` new, preparing, ready, served); intents by device kind are the intent registry | |
| 93 tokens | `E order.token_no`, `check.token_no` (display numbers) | |
| 96 customer data visibility | `E check.customer_name`, `customer_phone` (`pii`); `B BillDetail.customer_name` needs `report.view.outlet` | |
| 97 unsent lines at settlement, served-only | `E check.served_only`, `outlet_settings.served_default_counter` | |
| 102 to 106, 108, 110 discounts, service charge | `E order_line.discount_*`, `comp`, `check.discount_*`, `billing_settings.discount_limit_bp`, `service_charge_bp`; `B setDiscountLimit`; `X` TV-017 to TV-033 | Reason code is mandatory on the entity (`discount_reason_code_id`) |
| 113, 114 number at settle, crash between finalise and print | `E bill.number` (`doc_number`), `billing_settings.number_at`; `B setNumberingMode`; `O getOpenCheckCount` (guard) | Allocation and transaction are client-core |
| 115, 116, 131 printing layout | `E printer`, `print_route`, `receipt_profile` | Rendering golden files are client-core |
| 118 under Rs 200 gets its own number | `E bill` (one row per sale) | |
| 122 credit note in the day's tax summary | `B getTaxSummaryReport` (by `invoice_date`; credits separate); `X` TV-048 to TV-054 | |
| 127 fallback printer | `E print_route`, `printer` | Print jobs are local (server-only, not synced) |
| 129 retention | `B listBills`, `getBill`, `listCreditNotes` (no delete operation) | |
| 136 card reference at most 4 digits | `E payment.reference` (`max_length 40`; rule in README), `B Payment.reference` | Card limit is a client rule; field note says so |
| 139 refund vs credit note | `E refund`, `credit_note`; `B listRefunds`, `getCreditNote` | |
| 141 zero invoice vs internal close | `E check.status closed_internal`, `internal_consumption`; `B listInternalConsumptions`; `X` TV-016, TV-028 | Provisional (O2-1) |
| 142 no sale | `E cash_event.kind no_sale` | |
| 153 no reopen | `E business_day.status` (`rank` open, closed); no reopen operation | |
| 156, 158 business date vs invoice date, open tail | `B getTaxSummaryReport` (invoice date), `getDaySummaryReport` (business date); `RegisterSeries.state open_tail` | |
| 165 Z-report performance | Local computation; `B getDaySummaryReport` is the cloud counterpart | Performance is a load test |
| 175, 257 role templates, allowances separate | `common/permissions.yaml` (allowance permissions are separate keys); `make lint-specs` | Role templates themselves are identity data |
| 182 waiter device cannot finalise | Intent registry (device kinds) | Not delivered here |
| 207 entity schemas declare policy | `E` every file; `make lint-entities` (`cmd/validate-entities`) | |
| 217, 225 verification | `B Verification`, `VerificationStatus`, `listBills?verification=`, `listBillingExceptions`; `Ev billing.tax_verification.flagged` | |
| 218 no tenant-defined rate | No operation creates a rate; `B TaxRule` is read-only for tenants; `B` vendor routes admin only | |
| 230 integer thousandths | `E *_milli`; `X` | |
| 237, 241, 242 pre-bill, present records, numbering default | `E check_present`, `check_present_change`; `B BillingSettings.number_at` (default settle), `setNumberingMode` (409 `open_checks_exist`); `O getPresentLog` | |
| 248, 250, 254, 256, 294 allowances and re-bill | `E bill.rebill_group_id`, `credit_note.rebill_group_id`, `billing_settings` limits; `B getDiscountReport` (kinds `rebill`, `comp`, `internal_closure`, `open_item`); detector `allowance exceeded` | Count per shift is a device rule re-counted by detectors |
| 267, 275 reconciliation, manual entry | `B listBusinessDayRevisions`, `getBusinessDay`, `getBillingProjectionDigest`, `listDocumentGaps` (`kind manual_book`); `E bill.source_kind manual_book`, `book_total_paise`; `T registerManualBookSeries` | |
| 284, 289 captain code, open item | `menu.open_item` permission; captain-code mode is not specified in the contract (switched off, ADR needed) | |

### Offline `[OFFLINE]` criteria

These are exercised against the entities with the sync engine and the simulator, not over HTTP. The contract's part is the conflict
policy: AC 6 price conflicts (`lww_review`), AC 77 (`rank`), double payment and line-on-two-bills (detectors on `payment`,
`order_line`), AC 153/154 (`business_day` UUIDv5 id and `rank`, `day_close` facts), bill-book double entry (`bill` uuidv5 id), blackout
(`kot_handover`, `outlet_power_profile`), T9 convergence (`getOrdersProjectionDigest`, `getBillingProjectionDigest`).

## Admin A1, section 8

| AC | Operations | Note |
|---|---|---|
| 8 checklist is facts only | Derived by `admin` from `T getOrganisationSubscription`, `B` and identity reads; no checklist route here | `admin` stores nothing |
| 17 price validation | `T createPlan`, `createPlanVersion` (`Money`, `Cycle` enum, INR only) | |
| 21, 22 plan assignment atomic, unknown feature key | `T startSubscription`, `changeSubscription`; `Ev tenancy.subscription.changed` | Entitlement rows are internal to tenancy |
| 27 to 30 charge GST | `T raiseCharge` (`Charge` stores `cgst`, `sgst`, `igst`), `createBillingConfiguration` | E1 example is the `Charge` example (129900, 11691, 11691, 153282) |
| 34, 40 append-only, idempotency | `T` every mutation takes `Idempotency-Key`; no update or delete on charges and payments | Role-level denial is an implementation test |
| 41 no GSTIN in audit, events, logs | `Ev tenancy.subscription.changed` (key and state only), `T LedgerListRow` (no GSTIN) | |
| 47, 48, 53 payment tolerance, validation | `T recordPayment` (422 `overpayment`), `reversePayment`, `Charge.outstanding` | |
| 74 signing refused | `B validateTaxRuleSet`, `signTaxRuleSet` (422), `TaxRuleSetValidation` | Runs the vectors |
| 87 `support_actable` only on `catalog.import` | `common/permissions.yaml`; `make lint-specs` | |
| 103 double passes the suite | `contract-tests/{catalog,orders,billing,tenancy}` run from the double repos | |
| 104 realm and caller refusals | `x-service-callers`, `vendorBearerAuth` + `serviceAuth`; `make lint-specs` | |
| 109, 111 open trading day, trading-day event | `T suspendOrganisation`, `closeOrganisation` (409 `open_trading_day`); `Ev billing.trading_day.changed` (ids and a date only) | The "in progress" window is tenancy's rule |
| 112, 121 grant single-use, subject hash | `common/vendor.yaml VendorApprovalGrant`; `B publishTaxRuleSet`, `T` lifecycle ops (403 `grant.used`, `grant.expired`, `grant.subject_mismatch`) | Verification is go-auth and the services |
| 113 four approval kinds | `T` lifecycle ops, `B publishTaxRuleSet` | Approval record is identity's |
| 115 act mode checks both permissions | Not in this contract (identity); `admin.support.session.act` is in the catalogue | The spec says `admin.support.session.create`; the catalogue key is `admin.support.session.start` |
| 117, 120 lead time, one audit entry | `B publishTaxRuleSet` (422 `effective_date_too_soon`); `Ev billing.vendor_access.recorded` | Lead is deployment configuration |

## Gaps (not contract content)

Role-level write denial and isolation suites per tenant-owned table (go-service-standard tests); the sync intent registry
(`api-specs/sync/intents`, which needs ADR-0002 S4 fields per intent and is the pair of the entity files); TypeScript implementation
of the vectors; ESC/POS golden files; the admin-facing facade for the new tenancy and billing vendor routes (`openapi/admin`);
CSV export of reports (`report.export`, Should) other than the ledger export; item images and starter menu templates (server-only,
not in Phase 2 MVP). Role templates (owner, manager, cashier, waiter, kitchen) are data seeded by identity from the permission catalogue.

## Provisional choices (`x-provisional`) and what they need

| Choice | Where | Needs |
|---|---|---|
| `internal_consumption` is billing's non-tax internal document with its own register; `check.status` has `closed_internal` | `E`, `B listInternalConsumptions` | ADR-0014 amendment (O2-1) and the CA |
| `outlet_settings` (catalog) added; array facts as `*_json` strings; `receipt_profile` address is a normal setting | `E` | ADR-0014 R3 amendment |
| billing asks orders for the open-check count before `number_at` changes (synchronous, not on the trading path) | `O getOpenCheckCount` | ADR (or an event-fed table) |
| Packing charge taxed in its own class; service charge allocated pro rata by group | `X` TV-029 to TV-033 | CA |
| Round-off rule, inclusive-price rounding, ECO supply, composition, liquor | `X` vectors with `ca_confirm` (21 of 64) | CA |
| `menu.import` strong-session twin `catalog.import` (support act mode) | `C createMenuImport` | `security-reviewer` signature and IST-43 |
| Paper bill-book series `manual_book` registered through tenancy | `T registerManualBookSeries` | CA (parallel series under one GSTIN) |
| Projection digest algorithm `sha256-canon-v1` | `O`, `B` digests | go-common/sync |
| UUIDv5 namespace constant for deterministic ids | `E README` | go-common/sync |
