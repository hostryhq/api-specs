// Package common holds the shared contract components; this test keeps the vendor approval grant vectors (ADR-0014 A2.6)
// honest: every subject hash is the SHA-256 of its text, the example grant verifies under the example vendor-realm key and
// carries the subject hash of its kind, and the example in vendor.yaml is that same token.
package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type vectorFile struct {
	SubjectHash []struct {
		Kind        string            `json:"kind"`
		Fields      map[string]string `json:"fields"`
		Text        string            `json:"text"`
		SubjectHash string            `json:"subject_hash"`
	} `json:"subject_hash"`
	ExamplePack  map[string]string `json:"example_pack"`
	ExampleGrant struct {
		Token  string `json:"token"`
		Header struct {
			Alg string `json:"alg"`
			Kid string `json:"kid"`
		} `json:"header"`
		Claims map[string]any `json:"claims"`
	} `json:"example_grant"`
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVendorGrantVectors(t *testing.T) {
	raw, err := os.ReadFile("vendor-grant.vectors.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// subject hash rules (A2.6 item 2)
	want := map[string]string{
		"org_suspend":          "org_suspend\n{organisation_id}\nsuspended",
		"org_reinstate":        "org_reinstate\n{organisation_id}\nactive",
		"org_close":            "org_close\n{organisation_id}\nclosed",
		"tax_rule_set_publish": "tax_rule_set_publish\n{rule_set_id}\n{content_hash}\n{effective_date}",
	}
	seen := map[string]bool{}
	hashOf := map[string]string{}
	for _, c := range v.SubjectHash {
		text := want[c.Kind]
		for k, val := range c.Fields {
			text = strings.ReplaceAll(text, "{"+k+"}", val)
		}
		if text != c.Text || strings.Contains(text, "{") || strings.HasSuffix(text, "\n") {
			t.Errorf("%s: text %q is not the kind's template filled with its fields", c.Kind, c.Text)
		}
		h := sha256.Sum256([]byte(c.Text))
		if hex.EncodeToString(h[:]) != c.SubjectHash {
			t.Errorf("%s: subject_hash %s is not sha256(text)", c.Kind, c.SubjectHash)
		}
		seen[c.Kind] = true
		hashOf[c.Kind] = c.SubjectHash
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("no subject hash vector for kind %s", k)
		}
	}
	// the example grant (A2.6 item 1)
	parts := strings.Split(v.ExampleGrant.Token, ".")
	if len(parts) != 3 {
		t.Fatal("the example grant is not a compact JWS")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b64(t, v.ExamplePack[v.ExampleGrant.Header.Kid]))
	if err != nil {
		t.Fatal(err)
	}
	sig := b64(t, parts[2])
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if v.ExampleGrant.Header.Alg != "ES256" || !ecdsa.VerifyASN1(pub, h[:], der) {
		t.Error("the example grant does not verify under the example vendor-realm key")
	}
	var claims map[string]any
	if err := json.Unmarshal(b64(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["subject_hash"] != hashOf[claims["kind"].(string)] {
		t.Error("the example grant's subject_hash is not the vector of its kind")
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != 300 || claims["typ"] != "vendor_approval" || claims["realm"] != "vendor" {
		t.Error("the example grant claims break A2.6 (exp = iat + 300, typ, realm)")
	}
	// the examples in vendor.yaml are the same token and claims
	b, err := os.ReadFile("vendor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var y struct {
		Components struct {
			Parameters struct {
				Grant struct {
					Example string `yaml:"example"`
				} `yaml:"VendorApprovalGrant"`
			} `yaml:"parameters"`
			Schemas struct {
				Claims struct {
					Example map[string]any `yaml:"example"`
				} `yaml:"VendorApprovalGrantClaims"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	if y.Components.Parameters.Grant.Example != v.ExampleGrant.Token {
		t.Error("vendor.yaml's header example is not the vector's example grant")
	}
	ex := y.Components.Schemas.Claims.Example
	for k, want := range claims {
		got := ex[k]
		if f, ok := want.(float64); ok {
			if gi, ok := got.(int); !ok || float64(gi) != f {
				t.Errorf("claims example %s is %v, the token carries %v", k, got, want)
			}
		} else if got != want {
			t.Errorf("claims example %s is %v, the token carries %v", k, got, want)
		}
	}
}
