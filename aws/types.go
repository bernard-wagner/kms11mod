package main

import (
	"crypto/x509"

	"github.com/aws/aws-sdk-go/service/kms"
)

var kmsSignatureAlgorithmProperties = map[string]struct {
	PubKeyAlgo         x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
}{
	kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256: {x509.RSA, x509.SHA256WithRSA},
	kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384: {x509.RSA, x509.SHA384WithRSA},
	kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512: {x509.RSA, x509.SHA512WithRSA},
	kms.SigningAlgorithmSpecEcdsaSha256:          {x509.ECDSA, x509.ECDSAWithSHA256},
	kms.SigningAlgorithmSpecEcdsaSha384:          {x509.ECDSA, x509.ECDSAWithSHA384},
	kms.SigningAlgorithmSpecEcdsaSha512:          {x509.ECDSA, x509.ECDSAWithSHA512},
}
