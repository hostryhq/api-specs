// Package syncspec checks the sync contract of record against itself: the shared vectors (ADR-0002 S15) are internally
// correct, and every example in openapi/sync/v1/openapi.yaml is verifiable (body hash, chain, seal signature), so an example
// cannot drift from the protocol. The engines (go-common/sync, client-core) run the same vectors on their own code.
package syncspec

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	ExamplePack map[string]string `json:"example_pack"`
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
