package kms11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
)

var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

var SignatureAlgorithmDetails = map[x509.SignatureAlgorithm]struct {
	PubKeyAlgo x509.PublicKeyAlgorithm
	Hash       crypto.Hash
}{
	x509.MD2WithRSA:       {x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	x509.MD5WithRSA:       {x509.RSA, crypto.MD5},
	x509.SHA1WithRSA:      {x509.RSA, crypto.SHA1},
	x509.SHA256WithRSA:    {x509.RSA, crypto.SHA256},
	x509.SHA384WithRSA:    {x509.RSA, crypto.SHA384},
	x509.SHA512WithRSA:    {x509.RSA, crypto.SHA512},
	x509.SHA256WithRSAPSS: {x509.RSA, crypto.SHA256},
	x509.SHA384WithRSAPSS: {x509.RSA, crypto.SHA384},
	x509.SHA512WithRSAPSS: {x509.RSA, crypto.SHA512},
	x509.DSAWithSHA1:      {x509.DSA, crypto.SHA1},
	x509.DSAWithSHA256:    {x509.DSA, crypto.SHA256},
	x509.ECDSAWithSHA1:    {x509.ECDSA, crypto.SHA1},
	x509.ECDSAWithSHA256:  {x509.ECDSA, crypto.SHA256},
	x509.ECDSAWithSHA384:  {x509.ECDSA, crypto.SHA384},
	x509.ECDSAWithSHA512:  {x509.ECDSA, crypto.SHA512},
	x509.PureEd25519:      {x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

func GetPublicKeyAlgorithm(privKey crypto.Signer) x509.PublicKeyAlgorithm {
	switch privKey.Public().(type) {
	case *rsa.PublicKey:
		return x509.RSA
	case *ecdsa.PublicKey:
		return x509.ECDSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// Represents the two mathematical components of an ECDSA signature once
// decomposed.
type ECDSASignature struct {
	R, S *big.Int
}

func FormatSignature(privKey crypto.Signer, signature []byte) []byte {
	switch privKey.Public().(type) {
	case *ecdsa.PublicKey:
		sig := &ECDSASignature{}
		if _, err := asn1.Unmarshal(signature, sig); err == nil {
			return append(sig.R.Bytes(), sig.S.Bytes()...)
		}

	}
	return signature
}

func IsRSAPSS(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}
