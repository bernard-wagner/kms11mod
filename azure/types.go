package main

import (
	"crypto/x509"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
)

var signatureAlgorithmProperties = map[keyvault.JSONWebKeySignatureAlgorithm]struct {
	PubKeyAlgo         x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
}{
	keyvault.RS256: {x509.RSA, x509.SHA256WithRSA},
	keyvault.RS384: {x509.RSA, x509.SHA384WithRSA},
	keyvault.RS512: {x509.RSA, x509.SHA512WithRSA},
	keyvault.ES256: {x509.ECDSA, x509.ECDSAWithSHA256},
	keyvault.ES384: {x509.ECDSA, x509.ECDSAWithSHA384},
	keyvault.ES512: {x509.ECDSA, x509.ECDSAWithSHA512},
}

func parseID(id string) (baseURI string, name string, version string) {
	base := strings.ReplaceAll(id, "https://", "")
	parts := strings.Split(base, "/")
	if len(parts) > 1 {
		baseURI = "https://" + parts[0]
	}
	if len(parts) > 2 {
		name = parts[2]
	}
	if len(parts) > 3 {
		version = parts[3]
	}
	return
}

func keyVersion(key keyvault.JSONWebKey) string {
	return strings.Split(strings.SplitAfter(*key.Kid, "/keys/")[1], "/")[1]
}
