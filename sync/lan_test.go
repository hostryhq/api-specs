package syncspec

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/hostryhq/api-specs/internal/canon"
)

type lanVectors struct {
	LAN struct {
		Now         int64
		IdentityKey struct{ Kid, Pub string } `json:"identity_key"`
		TLSSPKIDER  string                    `json:"tls_spki_der"`
		SPKI        string
		RelaySPKI   string `json:"relay_spki"`
		NonceD      string `json:"nonce_d"`
		NonceH      string `json:"nonce_h"`
		Hub, Device struct {
			DeviceID   string `json:"device_id"`
			Pub        string
			Credential string
		}
		ProofCases []struct {
			Case, Role, Message, Sig string
			SignerPub                string `json:"signer_pub"`
			Valid                    bool
		} `json:"proof_cases"`
		CredentialCases []struct {
			Case, Credential string
			ExpectKind       string `json:"expect_kind"`
			ExpectOutlet     string `json:"expect_outlet"`
			Valid            bool
			Reason           *string
		} `json:"credential_cases"`
		Session struct {
			TTLSeconds int `json:"ttl_seconds"`
			TokenCases []struct {
				Token string
				Valid bool
			} `json:"token_cases"`
		}
	} `json:"lan_handshake"`
}

// judgeCredential applies the credential checks of ADR-0002 A3.1 item 4 that need no pack state.
func judgeCredential(idPub, jws, kind, outlet string, now int64) string {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || !verify(idPub, parts[0]+"."+parts[1], parts[2]) {
		return "signature"
	}
	pl, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "signature"
	}
	var m map[string]any
	if json.Unmarshal(pl, &m) != nil {
		return "signature"
	}
	gotKind, _ := m["kind"].(string)
	gotOutlet, _ := m["outlet_id"].(string)
	notAfter, _ := m["not_after"].(float64)
	switch {
	case int64(notAfter) < now:
		return "expired"
	case gotOutlet != outlet:
		return "outlet"
	case gotKind != kind:
		return "kind"
	}
	return ""
}

func TestLANHandshakeVectors(t *testing.T) {
	b, err := os.ReadFile("conformance/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v lanVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	l := v.LAN
	if len(l.ProofCases) < 5 || len(l.CredentialCases) < 6 {
		t.Fatal("lan_handshake vectors are required (ADR-0002 A3.6)")
	}
	der, err := base64.RawURLEncoding.DecodeString(l.TLSSPKIDER)
	if err != nil || sum(string(der)) != l.SPKI {
		t.Errorf("spki is not the SHA-256 of the DER SubjectPublicKeyInfo (%v)", err)
	}
	for _, c := range l.ProofCases {
		tag := "hostry-lan-" + c.Role + "-v1"
		want := strings.Join([]string{tag, l.NonceD, l.NonceH, l.Device.DeviceID, l.Hub.DeviceID, l.SPKI}, "\n")
		if c.Valid && c.Message != want {
			t.Errorf("%s: message is not tag, nonces, ids and spki joined by newlines", c.Case)
		}
		if got := verify(c.SignerPub, c.Message, c.Sig); got != c.Valid {
			t.Errorf("%s: signature valid=%v, vector says %v", c.Case, got, c.Valid)
		}
		if strings.Contains(c.Case, "relay") && !strings.HasSuffix(c.Message, l.RelaySPKI) {
			t.Errorf("%s: relay case must end in the relay's spki", c.Case)
		}
	}
	for _, c := range l.CredentialCases {
		got := judgeCredential(l.IdentityKey.Pub, c.Credential, c.ExpectKind, c.ExpectOutlet, l.Now)
		want := ""
		if c.Reason != nil {
			want = *c.Reason
		}
		if got != want || (got == "") != c.Valid {
			t.Errorf("%s: judged %q, vector says valid=%v reason %q", c.Case, got, c.Valid, want)
		}
	}
	if l.Session.TTLSeconds != 900 {
		t.Errorf("session ttl %d, ADR-0002 A3.1 item 5 says 900", l.Session.TTLSeconds)
	}
	for _, c := range l.Session.TokenCases {
		raw, err := base64.RawURLEncoding.DecodeString(c.Token)
		if ok := err == nil && len(raw) == 32 && len(c.Token) == 43; ok != c.Valid {
			t.Errorf("token %q: valid=%v, vector says %v", c.Token, ok, c.Valid)
		}
	}
}

// The recordDeviceDrained request example is verifiable: its signature verifies under a published drain example key and
// drained_through is exactly the statement's streams (round 6).
func TestDrainExampleVerifies(t *testing.T) {
	v := load(t)
	b, err := os.ReadFile("../openapi/identity/v1/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Example struct {
						DrainedThrough []struct {
							Stream string
							Seq    int64
						} `yaml:"drained_through"`
						Statement map[string]any `yaml:"statement"`
					} `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"requestBody"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ex := doc.Paths["/internal/v1/devices/{device_id}/drain"]["put"].RequestBody.Content["application/json"].Example
	if ex.Statement == nil {
		t.Fatal("recordDeviceDrained has no statement example")
	}
	sig, _ := ex.Statement["sig"].(string)
	unsigned := map[string]any{}
	for k, val := range ex.Statement {
		if k != "sig" {
			unsigned[k] = val
		}
	}
	j, err := canon.JCS(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range v.DrainStatement {
		if verify(c.Pub, "hostry-drain-v1\n"+string(j), sig) {
			found = true
		}
	}
	if !found {
		t.Error("the recordDeviceDrained example signature does not verify under any published drain example key")
	}
	streams, _ := ex.Statement["streams"].([]any)
	if len(streams) != len(ex.DrainedThrough) {
		t.Fatalf("drained_through has %d streams, the statement %d", len(ex.DrainedThrough), len(streams))
	}
	for i, s := range streams {
		m, _ := s.(map[string]any)
		seq, _ := m["seq"].(int)
		if m["stream"] != ex.DrainedThrough[i].Stream || int64(seq) != ex.DrainedThrough[i].Seq {
			t.Errorf("drained_through[%d] differs from the statement's stream %v", i, m)
		}
	}
}
