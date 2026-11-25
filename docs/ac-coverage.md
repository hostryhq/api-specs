# Admin A0 acceptance-criteria coverage

Maps each `[API]` criterion of `docs/product/admin-a0-spec.md` (sections 8.2 and 8.3) to the operations that express it, then
shows how the `[E2E]` admin-panel criteria (8.1) land on the admin API. `operationId`s are unique across a document; the owning
document is `I` identity, `T` tenancy, `A` admin. A criterion is "expressed" when the contract states the inputs, outputs, errors
and, where it can, the rule. Rules about storage, logs, database roles and isolation suites are implementation tests, not
contract content; they are listed as gaps at the end.

## 8.2 Identity (AC-ID)

| AC | Operations (document) | Note |
|---|---|---|
| ID-1 vendor credential, realm | `createVendorSession` (I); `getVendorJwks` (I); security scheme `vendorBearerAuth` | Vendor issuer and audience are separate from the tenant realm |
| ID-2 realm rejection | every operation: `x-permission` realm is checked by `make lint-specs` (admin.* only on vendor routes, tenant permissions only on tenant routes); `support_viewable` only on reads | Runtime refusal is a go-auth/service test; refusal is 401 `auth.invalid_token` |
| ID-4 TOTP once | `createVendorSession` (401 `vendor.sign_in_failed`) | |
| ID-5 lockout, per-address limit | `createVendorSession` (same 401 for lockout and wrong password) | |
| ID-6 setup link once, 24 h | `beginVendorSetup`, `completeVendorSetup` (422 `setup_link_invalid`) | |
| ID-7 deactivated user | `updateVendorUser` (A: `updateVendorUser`), `renewVendorSession`, `startSupportSession`, `endSupportSession` | Sessions end in the same operation |
| ID-8 support session | `startSupportSession` (I, A); schema `SupportToken` lists the claims (realm tenant, typ support, tid, sid, mode, ticket); 422 on duration over 60, empty ticket, short reason | |
| ID-9 refresh inside session | `renewSupportToken` (409 `support_session_ended`) | |
| ID-10 support token limits | `x-permission` catalogue flags (`support_viewable` reads only; `strong_only` never in a support token); foreign organisation 404 on every tenant read | 403/403/404 are runtime checks of the same contract |
| ID-11 act mode | `startSupportSession` (422 `mode_not_supported`) | |
| ID-12 tenant audit of support | `listAuditEntries` (I), `startSupportSession`, `endSupportSession`; event `tenancy.vendor_access.recorded` | Fail-closed on audit write is behavioural |
| ID-13 owner reads audit | `listAuditEntries` (I) | |
| ID-14 invitation by service | `createOwnerInvitation` (I, `x-service-callers: [admin]`); 14-day expiry; repeat returns same | |
| ID-15 OTP only for known | `createOtpChallenge` (identical 202, 429 with Retry-After) | |
| ID-16 accept by OTP | `createSession` (`invitation_accepted`) | |
| ID-17 cancelled/expired, resend | `cancelOwnerInvitation`, `renewOwnerInvitation`, `createOtpChallenge` | |
| ID-18 owner-mobile lookup | `lookupOrganisationsByOwnerMobile` (I): ids only, exact number, audited | |
| ID-19 vendor device list | `listOrganisationDevices`, `getOrganisationDevice` (I, A) | Closed schema `VendorDevice` |
| ID-20 vendor revoke | `revokeOrganisationDevice` (I, A); events `identity.device.revoked`, vendor and tenant audit | `listRevocations` for the gateway bound |
| ID-21 revoke repeat | `revokeOrganisationDevice` (`outcome: already_revoked`, `changed: false`) | |
| ID-22 closed schemas, deny list | `VendorDevice`, `VendorAuditEntry`, `OwnerInvitation`, `OwnerLookupResult`, `VendorApproval`, `Member`, `Device`, `Role` all `additionalProperties: false` and carry no number, email, PIN verifier, proof key or public key | |
| ID-24 double passes suite | `contract-tests/identity` (run with `HOSTRY_CONTRACT_EXPECT_EXAMPLES=1` against the double) | The double lives in `svc-identity` |

## 8.3 Tenancy (AC-TEN)

| AC | Operations (document) | Note |
|---|---|---|
| TEN-1 create organisation | `createOrganisation` (T, A) | |
| TEN-2 tenant/support token refused | `createOrganisation`: `admin.org.create` is a vendor-realm permission | |
| TEN-3 idempotency | `createOrganisation` (`Idempotency-Key`; replay returns first result) | |
| TEN-4 invalid input | `createOrganisation` (422 with field errors) | |
| TEN-5 GSTIN in use | `createOrganisation`, `verifyTaxRegistration` (409 `gstin_in_use`); tenant `createTaxRegistration` deliberately gives no such answer (ADR-0003 A1.1) | |
| TEN-6 no series, no entitlements | `createOrganisation` creates neither; series come only from `issueDocumentSeries` (I only caller) | |
| TEN-7 directory paging and search | `listOrganisationDirectory` (T), `listOrganisations` (A): `q`, `status`, `organisation_ids`, cursor, `VendorLimit` max 100 | |
| TEN-8 closed directory schema | `DirectoryOrganisation`, `DirectoryPage`, `OrganisationDetail` closed | |
| TEN-9 support-viewable reads | `getCurrentOrganisation`, `listBrands`, `listOutlets`, `listTaxRegistrations`, `listDocumentSeries`, `getOrganisationSettings` (T); `support_viewable` flags | |
| TEN-10 vendor token, no session | vendor realm vs tenant realm permissions; A support-view operations answer 403 `support_session_required` | |
| TEN-12 no lifecycle change | none exists; `OrganisationStatus` is read-only in every schema | |
| TEN-15 double passes suite | `contract-tests/tenancy` | Double lives in `svc-tenancy` |
| TEN-20 reject a registration | `rejectTaxRegistration` (T, vendor; only while unverified) | Added in the fix pass after Phase 1 implementation |
| ADR-0003 A1.1 item 6 close registration and series | `closeTaxRegistration` (T; step-up; 409 while an active outlet references it) | Added in the fix pass |

## 8.1 Admin panel criteria on the admin API (selected [E2E])

| AC-A0 | Operations (A) |
|---|---|
| 1-3, 7-9 sign-in, sessions, CSRF | `signIn`, `getSession`, `signOut`; cookie scheme `sessionCookie`; `X-CSRF-Token` on every mutation; 403 `csrf_failed` |
| 5-6 setup | `beginAccountSetup`, `completeAccountSetup` |
| 10-12 vendor staff | `listVendorUsers`, `createVendorUser`, `updateVendorUser` (409 `last_platform_admin`, `cannot_deactivate_self`), `resetVendorUserTotp` |
| 13 role matrix | `x-permission` on every operation against `vendor_roles` in `common/permissions.yaml` |
| 14-20 directory | `listOrganisations` (`owner_status_available`), `getOrganisation` |
| 21-30 create | `createOrganisation` (`state: complete|incomplete`), `createOwnerInvitation` (retry), 409 `gstin_in_use`, 422 |
| two-person approvals (ADR-0005 A2.3, ADR-0014 A1.3) | `fileVendorApproval`, `listVendorApprovals`, `getVendorApproval`, `approveVendorApproval`, `claimCodeHalf`, `cancelVendorApproval`; kinds `sign_in_code`, `owner_recovery`, `device_revoke_over_quota`, `org_suspend`, `org_reinstate`, `org_close`, `tax_rule_set_publish`; the 409 `vendor_approval_required` of `revokeOrganisationDevice` is resolved here |
| 31-34 invitations | `renewOwnerInvitation`, `cancelOwnerInvitation`, `createOwnerInvitation` (re-issue after expiry), `getOrganisation` |
| 35-42 devices | `listOrganisationDevices`, `getOrganisationDevice`, `revokeOrganisationDevice` |
| 43-50 audit | `listAuditEntries` (filters, `support_session_id`); no update or delete operation exists |
| 51-61 support | `startSupportSession`, `getSupportSession`, `endSupportSession`, nine `*Support*` read operations |
| 64 offline | 503 `upstream_unavailable` on reads; no queued writes (contract has no deferred operation) |
| UI, quality, load (4, 18, 22, 36, 50, 62, 63, 65) | not API |

## Gaps (cannot be mapped to a contract)

- **ID-3** (hash-only password, no secrets in logs): storage and logging; an implementation test. The contract only guarantees that no response carries a password or TOTP secret (the one-time `totp_provisioning_uri` in setup is the enrolment itself).
- **ID-23** and **TEN-11** (database roles, RLS, T5 lint): database level.
- **TEN-13** (log lines carry ids and acting vendor user): logging.
- **TEN-14** (T1-T5, T10-T13 isolation suites): shared service test suites; the contract supplies only the 404 rule.
- Runtime refusals in ID-2, ID-10, ID-12: the contract states realms, flags and errors; enforcement is go-auth and service tests.

## Decisions taken in the contract, to confirm

- BR-32 says resend and cancel apply to `pending` or `expired`, while AC-A0-34 says an expired invitation is re-issued as a new one with the old staying expired. Contract: `renewOwnerInvitation` and `cancelOwnerInvitation` act on `pending` only; an expired invitation is replaced through `createOwnerInvitation`.
- Ticket reference pattern `^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$` (ADR-0013 V5 asks for a fixed pattern without giving it).
- Phone rule `+91` then `[6-9]` and nine digits, and the GSTIN regex, are format checks only until the `gst-invoicing-india` and `integrations-expert` data arrives.
- Gate permissions `admin.approval.create|read|decide` (a static `x-permission` cannot say "by kind"); kind permissions are in `x-permission-by-kind`.
- Header names: `Hostry-Service-Token`, `Hostry-Approval` (go-auth), `X-Vendor-Client-Address` (the staff address passed by `admin`, ADR-0013 V2.9; name chosen here), `X-CSRF-Token`.
