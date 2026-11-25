# Tax calculation specification, calc_v 1

The single specification of how a bill or credit note is computed (ADR-0014 R6). Two implementations must produce every
vector in `conformance/vectors.v1.json` to the paisa: TypeScript in `client-core/tax` (the device, offline) and Go in
`svc-billing` (which recomputes every finalised document and records `verified`, `mismatch`, `stale_rules`, `profile_mismatch`
or `manual_entry`; a bill is never altered or rejected). `reference/` holds a third, test-only Go implementation that proves
the vectors are self-consistent (`go test ./tax/...`). A difference blocks merge. Changing the calculation is a new `calc_v`
and a new vector file; `billing` keeps every `calc_v` a released client could have used.

Integers only: amounts in **paise**, quantities in **thousandths** of a unit, rates in **basis points**. Rates never appear
in code: they come from the rule set row selected for the document (`rule-set.schema.yaml`).

## Inputs

`regime` (`regular`, `composition`, `unregistered`), `price_mode` (`exclusive`, `inclusive`), `round_off` (bool), `rules`
(tax class to `{gst, cgst_bp, sgst_bp}`; already resolved from the rule set in force on the invoice date for the regime, the
outlet's specified-premises flag and the order channel), `lines` (`qty_milli`, `unit_price_paise`, `modifier_delta_paise`,
`tax_class`, optional line `discount`, `comp`), optional `bill_discount`, `service_charge_bp`, optional `packing`. Under `regular` a line or packing class absent from `rules` is the error `unknown_tax_class` (never non-GST; TV-065); the other regimes do not read `rules`.
A discount is `{kind: percent, value: basis points}` or `{kind: amount, value: paise}`.

## Steps (in order)

1. **Line value** = round half up of `max(0, unit + modifier delta) x qty_milli / 1000`. The unit never goes below zero (RM-M3).
2. **Line discount** (a comp line is a discount of its whole value): percent = round half up of `value x bp / 10000`; it may not
   exceed the value or 100 percent, else `discount_exceeds_value`. `net = value - discount`.
3. **Bill discount** on the sum of line nets: percent = round half up of `sum x bp / 10000`; amount as given; it may not exceed
   the sum. It is **allocated across lines by largest remainder** over the line nets (floor of `D x net / sum`, then one paisa
   each to the largest remainders, ties to the earlier line), so the parts sum exactly. Discounts apply **before tax**.
4. **Service charge** = round half up of `sum of discounted lines x service_charge_bp / 10000` (it is off by default in outlet
   settings). It is allocated across **tax groups** by largest remainder over group value (ties by tax class ascending). The
   non-GST group takes its share and it stays untaxed.
5. **Packing charge**: a fixed amount added to the group of its own tax class (provisional, CA).
6. **Tax groups** are the distinct tax classes, ordered by tax class. Group value = discounted lines + charge share.
   - Exclusive: `taxable = value`.
   - Inclusive: `taxable = round half up of value x 10000 / (10000 + cgst_bp + sgst_bp)`.
   - `cgst = round half up of taxable x cgst_bp / 10000`; `sgst` likewise. Tax is computed **per group, not per line**.
   - A group whose rule has `gst: false` (non-GST items, and every group under `composition` and `unregistered`) carries no
     tax; its value is the non-GST subtotal. A class with `gst: true` and zero rates (`exempt`) is a group with zero tax.
7. **Total and round-off.** Exclusive: pre-round total = non-GST subtotal + taxable + CGST + SGST. Inclusive: pre-round total =
   sum of group values (the guest pays the menu price). If `round_off` the total is the pre-round total rounded half up to
   the nearest rupee, else equal to it. `round_off = total - (non-GST + taxable + CGST + SGST)` is a signed separate line, never
   part of the tax base; in inclusive mode it also absorbs the paisa or two by which taxable plus tax differs from the gross.

## Credit note

The credited value of a line = round half up of `line value after all original discounts x credited qty / original qty`. Each
group's charge share is prorated with the group's credited value. The same group arithmetic, rounding and round-off then apply
to the credited group values. A full credit note therefore equals the bill to the paisa (a vector invariant); partial credit
notes of one bill may differ from the bill in total by rounding.

## Needs the CA

Every case with `ca_confirm: true` has a `note` naming the rule. Open points (they also sit in the `gst-invoicing-india` list):
tax on service charge and allocation of packing; whether the round-off is part of the taxable value or a separate line;
inclusive-price rounding; GST on complimentary and free supplies and on a zero-total bill; liquor (non-GST) in Tamil Nadu and
Kerala; the document form and rate for an aggregator (ECO) supply; what a composition dealer issues; the sum of credit notes
against one bill. Until the CA answers, the vectors pin the provisional behaviour so any change is deliberate, and the first rule
set is published as `unreviewed`.

## Files

| Path | Content |
|---|---|
| `rule-set.schema.yaml` | JSON Schema of a rule set document (what the vendor drafts, signs and publishes). |
| `rule-sets/draft-unreviewed.v1.yaml` | An example draft for tests and the admin panel's first load. Rates are data pending CA review, not a published version. |
| `conformance/vectors.v1.json` | 64 golden vectors: bills, credit notes and refused inputs. |
| `reference/` | Test-only Go reference and the conformance test. |
