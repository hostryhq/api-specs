package syncspec

import (
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
)

func ecdsaCurve() elliptic.Curve { return elliptic.P256() }

// rawToDER converts the wire form r||s (32 bytes each) to the ASN.1 form crypto/ecdsa verifies.
func rawToDER(raw []byte) []byte {
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	return der
}
