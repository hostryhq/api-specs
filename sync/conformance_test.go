// Package syncspec checks the sync contract of record against itself: the shared vectors (ADR-0002 S15) are internally
// correct, and every example in openapi/sync/v1/openapi.yaml is verifiable (body hash, chain, seal signature), so an example
// cannot drift from the protocol. The engines (go-common/sync, client-core) run the same vectors on their own code.
package syncspec

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/hostryhq/api-specs/internal/canon"
)

const (
	maxBody  = 262144
	maxPII   = 16384
	maxBatch = 200
)

type vectors struct {
	Hash []struct {
		Body string
		H    string
	}
	Genesis []struct {
		Origin, Stream, H string
	}
	SealMessage []struct {
		Origin, Stream string
		Seq            int64
		H, Message     string
	} `json:"seal_message"`
	EndorseMessage []struct {
		Origin, Stream  string
		Seq             int64
		H, Rec, Message string
	} `json:"endorse_message"`
	AttestMessage []struct {
		Origin, Stream      string
		Seq                 int64
		H, By, Rec, Message string
	} `json:"attest_message"`
	EndorseVerify []struct {
		Case, Pub, Origin, Stream string
		Seq                       int64
		H, Rec, Kid, Sig          string
		Valid                     bool
	} `json:"endorse_verify"`
	HLC []struct {
		Ms      int64
		Counter int
		Hex     string
	} `json:"hlc"`
	SizeLimit []struct {
		Field string
		Bytes int
		Valid bool
	} `json:"size_limit"`
	EmitBatch []struct {
		Ops   int
		Valid bool
	} `json:"emit_batch"`
	Canonical []struct {
		In, Out string
	} `json:"canonical"`
	PIICommit []struct {
		Value      json.RawMessage `json:"value"`
		Salt       string          `json:"salt"`
		JCS        string          `json:"jcs"`
		Commitment string          `json:"commitment"`
	} `json:"pii_commit"`
	DrainStatement []struct {
		Case          string
		Pub           string
		Statement     map[string]any
		SignedMessage string `json:"signed_message"`
		StatementJCS  string `json:"statement_jcs"`
		StatementHash string `json:"statement_hash"`
		SigValid      bool   `json:"sig_valid"`
	} `json:"drain_statement"`
	ExamplePack   map[string]string `json:"example_pack"`
	ApprovalProof struct {
		ProofKey string `json:"proof_key"`
		Cases    []struct {
			Case, Kind, Message, Proof, Intent string
			ActionHash                         string `json:"action_hash"`
			SessionID                          string `json:"session_id"`
			DeviceID                           string `json:"device_id"`
			MemberID                           string `json:"member_id"`
			PackV                              int    `json:"pack_v"`
			PinV                               int    `json:"pin_v"`
			OpenedAt                           string `json:"opened_at"`
			ApprovalID                         string `json:"approval_id"`
			Permission, Target                 string
			RequesterID                        string `json:"requester_id"`
			ApprovedAt                         string `json:"approved_at"`
			Reason                             string
		} `json:"cases"`
	} `json:"approval_proof"`
	ActionHash []struct {
		Case, Intent, Permission, Requester, Target, Reason string
		ApprovalID                                          string `json:"approval_id"`
		JCS                                                 string `json:"jcs"`
		ActionHash                                          string `json:"action_hash"`
	} `json:"action_hash"`
	DigestRow []struct {
		Case, Entity, ID string
		PIIFields        []string          `json:"pii_fields"`
		Fields           map[string]any    `json:"fields"`
		PIIValues        map[string]any    `json:"pii_values"`
		Commitments      map[string]string `json:"commitments"`
		RowText          string            `json:"row_text"`
		EntityHash       string            `json:"entity_hash"`
	} `json:"digest_row"`
	PIIPlacement struct {
		Cases []struct {
			Kind      string
			PIIServed bool `json:"pii_served"`
		} `json:"cases"`
	} `json:"pii_placement"`
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("conformance/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func verify(pub, msg, sig string) bool {
	pb, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		return false
	}
	k, err := ecdsa.ParseUncompressedPublicKey(ecdsaCurve(), pb)
	if err != nil {
		return false
	}
	sb, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(sb) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(msg))
	return ecdsa.VerifyASN1(k, h[:], rawToDER(sb))
}

func TestVectorsAreSelfConsistent(t *testing.T) {
	v := load(t)
	for _, c := range v.Hash {
		if got := sum(c.Body); got != c.H {
			t.Errorf("hash of %q: %s, vector says %s", c.Body, got, c.H)
		}
	}
	for _, c := range v.Genesis {
		if got := sum("hostry-genesis-v1\n" + c.Origin + "\n" + c.Stream); got != c.H {
			t.Errorf("genesis %s/%s: %s, vector says %s", c.Origin, c.Stream, got, c.H)
		}
	}
	for _, c := range v.SealMessage {
		if got := fmt.Sprintf("hostry-seal-v1\n%s\n%s\n%d\n%s", c.Origin, c.Stream, c.Seq, c.H); got != c.Message {
			t.Errorf("seal message %q, vector says %q", got, c.Message)
		}
	}
	for _, c := range v.EndorseMessage {
		if got := fmt.Sprintf("hostry-endorse-v1\n%s\n%s\n%d\n%s\n%s", c.Origin, c.Stream, c.Seq, c.H, c.Rec); got != c.Message {
			t.Errorf("endorse message %q, vector says %q", got, c.Message)
		}
	}
	for _, c := range v.AttestMessage {
		if got := fmt.Sprintf("hostry-attest-v1\n%s\n%s\n%d\n%s\n%s\n%s", c.Origin, c.Stream, c.Seq, c.H, c.By, c.Rec); got != c.Message {
			t.Errorf("attest message %q, vector says %q", got, c.Message)
		}
	}
	for _, c := range v.EndorseVerify {
		msg := fmt.Sprintf("hostry-endorse-v1\n%s\n%s\n%d\n%s\n%s", c.Origin, c.Stream, c.Seq, c.H, c.Rec)
		if got := verify(c.Pub, msg, c.Sig); got != c.Valid {
			t.Errorf("endorsement case %q: valid=%v, vector says %v", c.Case, got, c.Valid)
		}
	}
	for _, c := range v.HLC {
		if got := fmt.Sprintf("%012x%04x", c.Ms, c.Counter); got != c.Hex {
			t.Errorf("hlc %d/%d: %s, vector says %s", c.Ms, c.Counter, got, c.Hex)
		}
	}
	for _, c := range v.SizeLimit {
		limit := maxBody
		if c.Field == "pii" {
			limit = maxPII
		}
		if (c.Bytes <= limit) != c.Valid {
			t.Errorf("size vector %s %d bytes: valid=%v disagrees with the limit %d", c.Field, c.Bytes, c.Valid, limit)
		}
	}
	for _, c := range v.Canonical {
		got, err := canon.JCSText(c.In)
		if err != nil || string(got) != c.Out {
			t.Errorf("canonical form of %s: %s (%v), vector says %s", c.In, got, err, c.Out)
		}
	}
	if len(v.PIICommit) < 4 {
		t.Error("pii_commit vectors are required (security ruling SR-2)")
	}
	for _, c := range v.PIICommit {
		salt, err := base64.RawURLEncoding.DecodeString(c.Salt)
		if err != nil || len(salt) != 16 {
			t.Errorf("pii_commit salt %q must be 16 bytes of base64url", c.Salt)
			continue
		}
		got, err := canon.JCSText(string(c.Value))
		if err != nil || string(got) != c.JCS {
			t.Errorf("pii_commit jcs of %s: %s (%v), vector says %s", c.Value, got, err, c.JCS)
		}
		if want := sum(string(salt) + c.JCS); want != c.Commitment {
			t.Errorf("pii_commit of %s: %s, vector says %s", c.Value, want, c.Commitment)
		}
	}
	if len(v.DrainStatement) < 3 {
		t.Error("drain_statement vectors are required (ADR-0005 A3.3)")
	}
	for _, c := range v.DrainStatement {
		sig, _ := c.Statement["sig"].(string)
		unsigned := map[string]any{}
		for k, val := range c.Statement {
			if k != "sig" {
				unsigned[k] = val
			}
		}
		j, err := canon.JCS(unsigned)
		if err != nil || "hostry-drain-v1\n"+string(j) != c.SignedMessage {
			t.Errorf("drain %q: signed message is not the tag plus the JCS of the object without sig (%v)", c.Case, err)
		}
		if got := verify(c.Pub, c.SignedMessage, sig); got != c.SigValid {
			t.Errorf("drain %q: signature valid=%v, vector says %v", c.Case, got, c.SigValid)
		}
		full, err := canon.JCS(c.Statement)
		if err != nil || string(full) != c.StatementJCS {
			t.Errorf("drain %q: JCS of the statement with sig differs from the vector (%v)", c.Case, err)
		}
		if got := sum(string(full)); got != c.StatementHash {
			t.Errorf("drain %q: statement_hash %s, vector says %s", c.Case, got, c.StatementHash)
		}
	}
	if len(v.ApprovalProof.Cases) < 4 {
		t.Error("approval_proof vectors are required (identity ApprovalProofMessageBound, ADR-0005 A3.1)")
	}
	key, err := base64.RawURLEncoding.DecodeString(v.ApprovalProof.ProofKey)
	if err != nil {
		t.Fatalf("approval_proof key: %v", err)
	}
	for _, c := range v.ApprovalProof.Cases {
		var msg string
		switch c.Kind {
		case "session":
			msg = strings.Join([]string{"session", c.SessionID, c.DeviceID, c.MemberID, strconv.Itoa(c.PackV), strconv.Itoa(c.PinV), c.OpenedAt}, "|")
		case "approval":
			j, _ := canon.JCS(map[string]any{"intent": c.Intent, "permission": c.Permission, "requester": c.RequesterID, "target": c.Target,
				"approval_id": c.ApprovalID, "reason": c.Reason})
			if want := "sha256:" + sum(string(j)); want != c.ActionHash {
				t.Errorf("approval_proof %q: action_hash %s, recomputed %s", c.Case, c.ActionHash, want)
			}
			msg = strings.Join([]string{"approval", c.ActionHash, c.DeviceID, c.MemberID, strconv.Itoa(c.PackV), strconv.Itoa(c.PinV), c.ApprovalID,
				c.Permission, strconv.Quote(c.Target), c.RequesterID, c.ApprovedAt, strconv.Quote(c.Reason)}, "|")
		default:
			t.Errorf("approval_proof %q: unknown kind %q", c.Case, c.Kind)
			continue
		}
		if msg != c.Message {
			t.Errorf("approval_proof %q: message %q, vector says %q", c.Case, msg, c.Message)
		}
		m := hmac.New(sha256.New, key)
		m.Write([]byte(c.Message))
		if got := base64.RawURLEncoding.EncodeToString(m.Sum(nil)); got != c.Proof {
			t.Errorf("approval_proof %q: proof %s, vector says %s", c.Case, got, c.Proof)
		}
	}
	if len(v.ActionHash) == 0 {
		t.Error("action_hash vectors are required (ADR-0014 A3.3 item 1)")
	}
	for _, c := range v.ActionHash {
		j, err := canon.JCS(map[string]any{"intent": c.Intent, "permission": c.Permission, "requester": c.Requester, "target": c.Target,
			"approval_id": c.ApprovalID, "reason": c.Reason})
		if err != nil || string(j) != c.JCS {
			t.Errorf("action_hash %q: JCS %s (%v), vector says %s", c.Case, j, err, c.JCS)
		}
		if want := "sha256:" + sum(string(j)); want != c.ActionHash {
			t.Errorf("action_hash %q: %s, vector says %s", c.Case, want, c.ActionHash)
		}
	}
	if len(v.DigestRow) < 3 {
		t.Error("digest_row vectors are required (ADR-0014 A3.2)")
	}
	for _, c := range v.DigestRow {
		pii := map[string]bool{}
		for _, f := range c.PIIFields {
			pii[f] = true
		}
		withValues := map[string]any{}
		for k, val := range c.Fields {
			withValues[k] = val
		}
		for k, val := range c.PIIValues {
			withValues[k] = val
		}
		for name, fields := range map[string]map[string]any{"holding the values": withValues, "holding none": c.Fields} {
			text, err := canon.RowText(c.ID, fields, pii, c.Commitments)
			if err != nil || text != c.RowText {
				t.Errorf("digest_row %q %s: %s (%v), vector says %s", c.Case, name, text, err, c.RowText)
			}
		}
		if _, h := canon.EntityHash(map[string]string{c.ID: c.RowText}); h != c.EntityHash {
			t.Errorf("digest_row %q: entity hash %s, vector says %s", c.Case, h, c.EntityHash)
		}
	}
	for _, c := range v.PIIPlacement.Cases {
		if want := c.Kind != "kds"; c.PIIServed != want {
			t.Errorf("pii_placement %s: served=%v, ADR-0014 A3.1 item 1 says %v", c.Kind, c.PIIServed, want)
		}
	}
	if len(v.PIIPlacement.Cases) < 5 {
		t.Error("pii_placement vectors cover pos, waiter, personal, hub and kds")
	}
	if len(v.SizeLimit) < 4 || len(v.EmitBatch) < 4 {
		t.Error("size_limit and emit_batch vectors are required (ADR-0014 A2.1 item 3, A2.2 item 1)")
	}
	for _, c := range v.EmitBatch {
		if (c.Ops >= 1 && c.Ops <= maxBatch) != c.Valid {
			t.Errorf("emit batch of %d ops: valid=%v disagrees with 1..%d", c.Ops, c.Valid, maxBatch)
		}
	}
}

type op struct {
	Origin, Stream string
	Seq            int64
	Ph, Tenant     string
}

type item struct {
	Origin string `yaml:"origin"`
	Stream string `yaml:"stream"`
	Seq    int64  `yaml:"seq"`
	H      string `yaml:"h"`
	Body   string `yaml:"body"`
}

// The push example is a real two-op chain from the genesis hash with a seal at seq 2 that verifies under the example pack.
func TestSpecExamplesVerify(t *testing.T) {
	v := load(t)
	b, err := os.ReadFile("../openapi/sync/v1/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Example struct {
						Items []item `yaml:"items"`
						Seals []struct {
							Origin, Stream string
							Seq            int64
							H, Kid, Sig    string
						} `yaml:"seals"`
					} `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"requestBody"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ex := doc.Paths["/sync/v1/push"]["post"].RequestBody.Content["application/json"].Example
	if len(ex.Items) == 0 {
		t.Fatal("pushOps has no example items")
	}
	prev := ""
	for i, it := range ex.Items {
		if got := sum(it.Body); got != it.H {
			t.Errorf("item %d: h is %s but sha256(body) is %s", it.Seq, it.H, got)
		}
		if len(it.Body) > maxBody {
			t.Errorf("item %d: body over the limit", it.Seq)
		}
		var o struct {
			Origin, Stream, Ph string
			Seq                int64
		}
		if err := json.Unmarshal([]byte(it.Body), &o); err != nil {
			t.Fatalf("item %d: body is not JSON: %v", it.Seq, err)
		}
		if o.Origin != it.Origin || o.Stream != it.Stream || o.Seq != it.Seq {
			t.Errorf("item %d: body names %s/%s/%d", it.Seq, o.Origin, o.Stream, o.Seq)
		}
		want := prev
		if i == 0 {
			want = sum("hostry-genesis-v1\n" + it.Origin + "\n" + it.Stream)
		}
		if o.Ph != want {
			t.Errorf("item %d: ph %s breaks the chain, want %s", it.Seq, o.Ph, want)
		}
		prev = it.H
	}
	for _, s := range ex.Seals {
		pub := v.ExamplePack[s.Kid]
		msg := fmt.Sprintf("hostry-seal-v1\n%s\n%s\n%d\n%s", s.Origin, s.Stream, s.Seq, s.H)
		if !verify(pub, msg, s.Sig) {
			t.Errorf("seal at %d does not verify under example key %s", s.Seq, s.Kid)
		}
	}
	if len(ex.Seals) == 0 {
		t.Error("the push example carries a seal")
	}
}
