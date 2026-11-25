// Command validate-intents checks the sync intent registry under sync/intents (ADR-0002 S4, ADR-0005 section 7, A2 and
// section 8, ADR-0014 R1): every intent has a class, a permission that is in the catalogue (and is not strong_only, because
// a strong-only action has no intent), the proof and session rules hold, every entity it touches exists in entities/ with
// a conflict policy that allows the mutation kind, all touched entities share the stream, the owner is one of the entity
// owners, documents and numbering agree with the entities' document-number fields, and every intent an entity file names
// in written_by_intents exists. Usage: validate-intents <repo-root>.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type intent struct {
	Intent     string   `yaml:"intent"`
	IntentV    int      `yaml:"intent_v"`
	Class      string   `yaml:"class"`
	Owner      string   `yaml:"owner"`
	Desc       string   `yaml:"description"`
	Permission *string  `yaml:"permission"`
	PermReason string   `yaml:"permission_reason"`
	AuthBy     []string `yaml:"authorised_online_by"`
	Proof      struct {
		Kind  string   `yaml:"kind"`
		Binds []string `yaml:"binds"`
	} `yaml:"proof"`
	Override  bool `yaml:"override"`
	Allowance *struct {
		Counter      string `yaml:"counter"`
		LimitSetting string `yaml:"limit_setting"`
		CheckedBy    string `yaml:"checked_by"`
	} `yaml:"allowance"`
	Above *struct {
		UseIntent          string `yaml:"use_intent"`
		ApprovalPermission string `yaml:"approval_permission"`
	} `yaml:"above_allowance"`
	Sessions    []string            `yaml:"sessions"`
	Kinds       []string            `yaml:"device_kinds"`
	Streams     []string            `yaml:"streams"`
	Numbering   string              `yaml:"numbering"`
	Documents   []string            `yaml:"documents"`
	Entities    map[string][]string `yaml:"entities"`
	Records     []string            `yaml:"records"`
	PIIFields   []string            `yaml:"pii_fields"`
	Idempotency string              `yaml:"idempotency"`
	Provisional string              `yaml:"x-provisional"`
}

type registryFile struct {
	Registry    string   `yaml:"registry"`
	RegistryV   int      `yaml:"registry_v"`
	Group       string   `yaml:"group"`
	Description string   `yaml:"description"`
	Intents     []intent `yaml:"intents"`
}

type perm struct {
	Key   string   `yaml:"key"`
	Realm string   `yaml:"realm"`
	Flags []string `yaml:"flags"`
}

type field struct {
	Policy    string `yaml:"policy"`
	DocNumber bool   `yaml:"doc_number"`
	PII       bool   `yaml:"pii"`
}

type entity struct {
	Entity      string `yaml:"entity"`
	Owner       string `yaml:"owner"`
	Stream      string `yaml:"stream"`
	Tombstone   bool   `yaml:"tombstone"`
	CloudOrigin bool   `yaml:"cloud_origin_only"`
	Guarded     bool   `yaml:"guarded"`
	Replicated  []struct {
		Service          string `yaml:"service"`
		Purpose          string `yaml:"purpose"`
		GuardedException string `yaml:"guarded_exception"`
	} `yaml:"replicated_to"`
	Fields  map[string]field `yaml:"fields"`
	Intents []string         `yaml:"written_by_intents"`
}

var (
	nameRe     = regexp.MustCompile(`^[a-z]+(\.[a-z_]+)+$`)
	classes    = set("trading", "config", "control")
	owners     = set("orders", "billing", "catalog", "identity", "gateway")
	sessionsT  = set("pin", "strong", "device")
	kindsT     = set("pos", "waiter", "kds", "personal", "cloud")
	streamsT   = set("outlet", "brand", "tenant")
	numberingT = set("none", "allocated", "typed")
	docsT      = set("tax_invoice", "bill_of_supply", "plain_bill", "credit_note")
	recordsT   = set("session", "approval", "series_activation", "series_close", "clock_confirmation", "sync_void", "pii_erase")
	mutKinds   = set("insert", "set", "delta", "rank", "del", "undel")
)

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range v {
		m[s] = true
	}
	return m
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-intents <repo-root>")
		os.Exit(2)
	}
	errs, summary := run(os.Args[1])
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "FAIL:", e)
		}
		os.Exit(1)
	}
	fmt.Println(summary)
}

func run(root string) (errs []string, summary string) {
	fail := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	var cat struct {
		Permissions []perm `yaml:"permissions"`
	}
	if b, err := os.ReadFile(filepath.Join(root, "common", "permissions.yaml")); err != nil {
		return []string{err.Error()}, ""
	} else if err := yaml.Unmarshal(b, &cat); err != nil {
		return []string{"permissions.yaml: " + err.Error()}, ""
	}
	perms := map[string]perm{}
	for _, p := range cat.Permissions {
		perms[p.Key] = p
	}
	hasFlag := func(p perm, f string) bool {
		for _, x := range p.Flags {
			if x == f {
				return true
			}
		}
		return false
	}

	ents := map[string]entity{}
	efiles, _ := filepath.Glob(filepath.Join(root, "entities", "*", "*.yaml"))
	for _, f := range efiles {
		b, err := os.ReadFile(f)
		if err != nil {
			fail("%s", err)
			continue
		}
		var e entity
		if err := yaml.Unmarshal(b, &e); err != nil {
			fail("%s: %v", f, err)
			continue
		}
		ents[e.Entity] = e
	}

	files, _ := filepath.Glob(filepath.Join(root, "sync", "intents", "*.yaml"))
	sort.Strings(files)
	if len(files) == 0 {
		return []string{"no intent files under sync/intents"}, ""
	}
	all := map[string]intent{}
	var order []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fail("%s", err)
			continue
		}
		var rf registryFile
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&rf); err != nil {
			fail("%s: %v", filepath.Base(f), err)
			continue
		}
		if rf.Registry != "sync-intents" || rf.RegistryV != 1 || !owners[rf.Group] {
			fail("%s: registry must be sync-intents, registry_v 1 and group one of the owners", filepath.Base(f))
		}
		for _, in := range rf.Intents {
			if _, dup := all[in.Intent]; dup {
				fail("%s: intent %s is declared twice", filepath.Base(f), in.Intent)
				continue
			}
			all[in.Intent] = in
			order = append(order, in.Intent)
		}
	}

	touched := map[string]map[string]bool{} // entity -> intents that touch it
	subs := map[string]map[string]bool{}    // namespace -> subscribing services
	for _, name := range order {
		in := all[name]
		id := "intent " + name
		if !nameRe.MatchString(name) {
			fail("%s: name must be <namespace>.<action>[.<qualifier>] in lower case", id)
		}
		if in.IntentV < 1 {
			fail("%s: intent_v must be 1 or more", id)
		}
		if !classes[in.Class] {
			fail("%s: class must be trading, config or control", id)
		}
		if !owners[in.Owner] {
			fail("%s: unknown owner %q", id, in.Owner)
		}
		if len(strings.TrimSpace(in.Desc)) < 20 {
			fail("%s: description is required", id)
		}
		if len(strings.TrimSpace(in.Idempotency)) < 30 {
			fail("%s: idempotency rule is required (what a replay does)", id)
		}
		cloud := len(in.Kinds) == 1 && in.Kinds[0] == "cloud"

		// permission
		var p perm
		if in.Permission == nil {
			if in.Class == "trading" {
				fail("%s: a trading intent needs a permission", id)
			}
			if strings.TrimSpace(in.PermReason) == "" {
				fail("%s: no permission needs permission_reason", id)
			}
			if in.Proof.Kind == "action" || in.Override {
				fail("%s: an action proof or override needs a permission", id)
			}
		} else {
			var ok bool
			p, ok = perms[*in.Permission]
			switch {
			case !ok:
				fail("%s: permission %s is not in common/permissions.yaml", id, *in.Permission)
			case p.Realm != "tenant":
				fail("%s: permission %s is not tenant-realm", id, *in.Permission)
			case hasFlag(p, "strong_only"):
				fail("%s: permission %s is strong_only; a strong-only action has no intent (ADR-0002 S4)", id, *in.Permission)
			}
		}
		for _, a := range in.AuthBy {
			if _, ok := perms[a]; !ok {
				fail("%s: authorised_online_by %s is not in the catalogue", id, a)
			}
		}
		if len(in.AuthBy) > 0 && !cloud {
			fail("%s: authorised_online_by belongs to cloud-origin intents", id)
		}

		// proof, override, allowance
		switch in.Proof.Kind {
		case "session":
			if len(in.Proof.Binds) > 0 {
				fail("%s: binds belong to an action proof", id)
			}
		case "action":
			if len(in.Proof.Binds) == 0 {
				fail("%s: an action proof must name the fields it binds", id)
			}
			if in.Permission != nil && !hasFlag(p, "sensitive") {
				fail("%s: an action proof needs a sensitive permission, %s is not", id, *in.Permission)
			}
			for _, s := range in.Sessions {
				if s == "device" {
					fail("%s: an action proof needs a member; a device session names none", id)
				}
			}
		default:
			fail("%s: proof.kind must be session or action", id)
		}
		if in.Override && in.Proof.Kind != "action" {
			fail("%s: override needs proof.kind action (ADR-0005 section 8)", id)
		}
		if in.Allowance != nil {
			if in.Proof.Kind != "session" || in.Override {
				fail("%s: an allowance verifies without an approval record (session proof, no override; ADR-0014 A1.5 item 6)", id)
			}
			if in.Allowance.Counter == "" || in.Allowance.LimitSetting == "" || in.Allowance.CheckedBy == "" {
				fail("%s: allowance needs counter, limit_setting and checked_by", id)
			}
			if in.Above == nil {
				fail("%s: allowance needs above_allowance (what is used beyond the limit)", id)
			} else if in.Above.UseIntent != "" {
				if _, ok := all[in.Above.UseIntent]; !ok {
					fail("%s: above_allowance.use_intent %s is not an intent", id, in.Above.UseIntent)
				}
			} else if _, ok := perms[in.Above.ApprovalPermission]; !ok {
				fail("%s: above_allowance.approval_permission %q is not in the catalogue", id, in.Above.ApprovalPermission)
			}
		} else if in.Above != nil {
			fail("%s: above_allowance without allowance", id)
		}

		// sessions and device kinds
		if len(in.Kinds) == 0 {
			fail("%s: device_kinds is empty", id)
		}
		for _, k := range in.Kinds {
			if !kindsT[k] {
				fail("%s: unknown device kind %s", id, k)
			}
		}
		if cloud {
			if len(in.Sessions) != 0 {
				fail("%s: a cloud-origin intent has no session", id)
			}
			if in.Class == "trading" {
				fail("%s: a cloud-origin intent is config or control, never trading", id)
			}
		} else {
			if len(in.Sessions) == 0 {
				fail("%s: sessions is empty", id)
			}
			for _, k := range in.Kinds {
				if k == "cloud" {
					fail("%s: cloud is the only kind of a cloud-origin intent", id)
				}
			}
		}
		for _, s := range in.Sessions {
			if !sessionsT[s] {
				fail("%s: unknown session type %s", id, s)
			}
		}
		// streams, entities, records
		if len(in.Streams) == 0 {
			fail("%s: streams is empty", id)
		}
		for _, s := range in.Streams {
			if !streamsT[s] {
				fail("%s: unknown stream %s", id, s)
			}
		}
		streamOK := set(in.Streams...)
		docEntity := false
		entOwners := map[string]bool{}
		for en, kinds := range in.Entities {
			e, ok := ents[en]
			if !ok {
				fail("%s: entity %s does not exist in entities/", id, en)
				continue
			}
			if touched[en] == nil {
				touched[en] = map[string]bool{}
			}
			touched[en][name] = true
			entOwners[e.Owner] = true
			if !streamOK[e.Stream] {
				fail("%s: entity %s is on stream %s, which the intent does not declare", id, en, e.Stream)
			}
			if e.CloudOrigin && !cloud {
				fail("%s: entity %s is cloud-origin only", id, en)
			}
			if len(kinds) == 0 {
				fail("%s: entity %s has no mutation kinds", id, en)
			}
			hasPol := func(pols ...string) bool {
				for _, f := range e.Fields {
					for _, p := range pols {
						if f.Policy == p {
							return true
						}
					}
				}
				return false
			}
			for _, k := range kinds {
				switch {
				case !mutKinds[k]:
					fail("%s: entity %s: unknown mutation kind %s", id, en, k)
				case k == "set" && !hasPol("lww", "lww_review"):
					fail("%s: entity %s has no lww field, so no set", id, en)
				case k == "delta" && !hasPol("delta"):
					fail("%s: entity %s has no delta field", id, en)
				case k == "rank" && !hasPol("rank"):
					fail("%s: entity %s has no rank field", id, en)
				case (k == "del" || k == "undel") && !e.Tombstone:
					fail("%s: entity %s is not a tombstone entity", id, en)
				}
				if k == "insert" {
					for _, f := range e.Fields {
						if f.DocNumber {
							docEntity = true
						}
					}
				}
			}
			if e.Guarded && in.Class == "config" && !cloud {
				fail("%s: guarded entity %s (money or tax) cannot be changed by a device config intent", id, en)
			}
		}
		for _, r := range in.Records {
			if !recordsT[r] {
				fail("%s: unknown protocol record %s", id, r)
			}
		}
		if len(in.Entities) == 0 && len(in.Records) == 0 {
			fail("%s: an intent touches at least one entity or protocol record", id)
		}
		if len(in.Entities) > 0 {
			switch {
			case in.Owner == "gateway" && cloud:
				// a generic cloud emit has no single entity owner
			case in.Owner == "identity" || in.Owner == "gateway":
				fail("%s: owner %s does not own entities", id, in.Owner)
			case !entOwners[in.Owner]:
				fail("%s: owner %s owns none of the touched entities", id, in.Owner)
			}
		} else if in.Owner != "identity" && in.Owner != "gateway" {
			fail("%s: an intent with no entity is owned by identity or gateway", id)
		}
		// A cloud-origin intent's owner owns every entity it touches: this is the emit caller check (ADR-0014 A2.3 item 3).
		if cloud && len(in.Entities) > 0 {
			for o := range entOwners {
				if o != in.Owner {
					fail("%s: cloud-origin intent owned by %s touches an entity of %s; the emit caller must own every entity", id, in.Owner, o)
				}
			}
		}
		// Subscribers of namespace N (ADR-0014 A2.1 item 6): owners and declared readers of every entity an intent of N may
		// touch, plus billing for the series records (A2.5 item 2).
		ns := name[:strings.Index(name, ".")]
		if subs[ns] == nil {
			subs[ns] = map[string]bool{}
		}
		for s := range entOwners {
			subs[ns][s] = true
		}
		for en := range in.Entities {
			for _, r := range ents[en].Replicated {
				subs[ns][r.Service] = true
			}
		}
		for _, r := range in.Records {
			if r == "series_activation" || r == "series_close" {
				subs[ns]["billing"] = true
			}
		}

		// numbering and documents
		if !numberingT[in.Numbering] {
			fail("%s: numbering must be none, allocated or typed", id)
		}
		for _, d := range in.Documents {
			if !docsT[d] {
				fail("%s: unknown document type %s", id, d)
			}
		}
		if (in.Numbering == "none") != (len(in.Documents) == 0) {
			fail("%s: documents are listed exactly when numbering is allocated or typed", id)
		}
		if docEntity != (in.Numbering != "none") {
			fail("%s: numbering %s disagrees with the entities (an insert into a doc_number entity is a numbered document)", id, in.Numbering)
		}
		if in.Numbering == "allocated" && in.Class != "trading" {
			fail("%s: only a trading intent allocates a legal number", id)
		}
		piiOK := map[string]bool{}
		for en := range in.Entities {
			for fn, f := range ents[en].Fields {
				if f.PII {
					piiOK[fn] = true
				}
			}
		}
		for _, pf := range in.PIIFields {
			if !piiOK[pf] {
				fail("%s: pii_fields %s is not a pii field of a touched entity", id, pf)
			}
		}
	}

	// entity files agree with the registry: an intent an entity names must exist and touch it.
	enames := make([]string, 0, len(ents))
	for n := range ents {
		enames = append(enames, n)
	}
	sort.Strings(enames)
	untouched := 0
	for _, n := range enames {
		for _, name := range ents[n].Intents {
			if _, ok := all[name]; !ok {
				fail("entity %s: written_by_intents names %s, which is not in the registry", n, name)
			} else if !touched[n][name] {
				fail("entity %s: written_by_intents names %s, but that intent does not list %s", n, name, n)
			}
		}
		if len(touched[n]) == 0 {
			untouched++
			fail("entity %s is written by no intent", n)
		}
	}
	// replicated_to (ADR-0014 A2.4): a read-only replica of another owner's reference entity.
	nrep := 0
	for _, n := range enames {
		e := ents[n]
		for _, r := range e.Replicated {
			nrep++
			if !owners[r.Service] || r.Service == "gateway" || r.Service == "identity" {
				fail("entity %s: replicated_to %q is not a service that applies synced entities", n, r.Service)
			}
			if r.Service == e.Owner {
				fail("entity %s: replicated_to names its own owner", n)
			}
			if strings.TrimSpace(r.Purpose) == "" {
				fail("entity %s: replicated_to %s needs a one-line purpose", n, r.Service)
			}
		}
		if len(e.Replicated) > 0 {
			for _, r := range e.Replicated {
				if e.Guarded && strings.TrimSpace(r.GuardedException) == "" {
					fail("entity %s is guarded (money or tax) and is never replicated (ADR-0014 A2.4 item 3) unless the entry states guarded_exception", n)
				}
			}
			for fn, f := range e.Fields {
				if f.PII {
					fail("entity %s: a replica holds no pii field, but %s is pii", n, fn)
				}
			}
		}
	}

	// the generated subscriptions of the sync.op event match the registries (ADR-0014 A2.1 item 6)
	evPath := filepath.Join(root, "events", "sync", "op.v1.yaml")
	if b, err := os.ReadFile(evPath); err != nil {
		fail("events/sync/op.v1.yaml: %v", err)
	} else {
		var ev struct {
			ByNS map[string][]string `yaml:"x-subscribers-by-namespace"`
			Subs []string            `yaml:"x-subscribers"`
		}
		if err := yaml.Unmarshal(b, &ev); err != nil {
			fail("events/sync/op.v1.yaml: %v", err)
		} else {
			union := map[string]bool{}
			for ns, want := range subs {
				got := set(ev.ByNS[ns]...)
				for w := range want {
					if !got[w] {
						fail("events/sync/op.v1.yaml: x-subscribers-by-namespace.%s lacks %s (regenerate from the registries)", ns, w)
					}
					union[w] = true
				}
				for g := range got {
					if !want[g] {
						fail("events/sync/op.v1.yaml: x-subscribers-by-namespace.%s lists %s, which owns or reads no entity of the namespace", ns, g)
					}
				}
			}
			for ns := range ev.ByNS {
				if _, ok := subs[ns]; !ok {
					fail("events/sync/op.v1.yaml: namespace %s has no intent", ns)
				}
			}
			if !equalSets(union, set(ev.Subs...)) {
				fail("events/sync/op.v1.yaml: x-subscribers must be the union of x-subscribers-by-namespace")
			}
		}
	}

	// x-emits-intent (ADR-0014 A2.3 item 3), checked both ways
	emitted := map[string]map[string]bool{} // intent -> permissions of its emitting operations
	specs, _ := filepath.Glob(filepath.Join(root, "openapi", "*", "v1", "openapi.yaml"))
	for _, f := range specs {
		svc := filepath.Base(filepath.Dir(filepath.Dir(f)))
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc struct {
			Paths map[string]map[string]any `yaml:"paths"`
		}
		if yaml.Unmarshal(b, &doc) != nil {
			continue
		}
		for path, item := range doc.Paths {
			for m, v := range item {
				op, _ := v.(map[string]any)
				name, _ := op["x-emits-intent"].(string)
				if name == "" {
					continue
				}
				at := fmt.Sprintf("%s %s %s", svc, strings.ToUpper(m), path)
				in, ok := all[name]
				switch {
				case !ok:
					fail("%s: x-emits-intent %s is not an intent", at, name)
					continue
				case len(in.Kinds) != 1 || in.Kinds[0] != "cloud":
					fail("%s: x-emits-intent %s is not a cloud-origin intent", at, name)
				case in.Owner != svc:
					fail("%s: x-emits-intent %s is owned by %s; only the owner emits it", at, name, in.Owner)
				}
				perm, _ := op["x-permission"].(string)
				okPerm := false
				for _, a := range in.AuthBy {
					if a == perm {
						okPerm = true
					}
				}
				if !okPerm {
					fail("%s: x-permission %s is not in authorised_online_by of %s", at, perm, name)
				}
				if emitted[name] == nil {
					emitted[name] = map[string]bool{}
				}
				emitted[name][perm] = true
				if w, ok := op["x-permission-widened-by"].(string); ok {
					emitted[name][w] = true
				}
			}
		}
	}
	for _, name := range order {
		in := all[name]
		if len(in.Kinds) == 1 && in.Kinds[0] == "cloud" && len(in.AuthBy) > 0 {
			if emitted[name] == nil {
				fail("intent %s is cloud-origin with authorised_online_by but no operation declares x-emits-intent: %s", name, name)
				continue
			}
			for _, a := range in.AuthBy {
				if !emitted[name][a] {
					fail("intent %s: authorised_online_by %s is the permission of no emitting operation", name, a)
				}
			}
		}
	}

	// emitOps x-service-callers are exactly the owners of cloud-origin intents (ADR-0014 A2.2 item 1)
	cloudOwners := map[string]bool{}
	for _, name := range order {
		in := all[name]
		if len(in.Kinds) == 1 && in.Kinds[0] == "cloud" && in.Owner != "gateway" {
			cloudOwners[in.Owner] = true
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "openapi", "sync", "v1", "openapi.yaml")); err == nil {
		var doc struct {
			Paths map[string]map[string]struct {
				Callers []string `yaml:"x-service-callers"`
			} `yaml:"paths"`
		}
		if yaml.Unmarshal(b, &doc) == nil {
			if !equalSets(cloudOwners, set(doc.Paths["/internal/v1/emit"]["post"].Callers...)) {
				fail("openapi/sync: emitOps x-service-callers must be exactly the owners of cloud-origin intents (%d owners)", len(cloudOwners))
			}
		}
	}

	counts := map[string]int{}
	for _, name := range order {
		counts[all[name].Class]++
	}
	summary = fmt.Sprintf("intents: %d intents (%d trading, %d config, %d control) in %d files; %d entities each written by at least one intent; %d replicas; sync.op subscribers and x-emits-intent agree",
		len(order), counts["trading"], counts["config"], counts["control"], len(files), len(enames)-untouched, nrep)
	return errs, summary
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
