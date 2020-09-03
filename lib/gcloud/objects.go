package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"math/big"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/bernard-wagner/kms11mod/internal/backend"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func generateID(keyName string) []byte {
	hash := crypto.SHA1.New()
	_, _ = hash.Write([]byte(keyName))
	return hash.Sum(nil)[0:6]
}

func cryptoKeyVersionToObjects(client *kms.KeyManagementClient, cryptoKeyVersion *kmspb.CryptoKeyVersion, label string) ([]backend.Object, error) {
	if label == "" {
		label = strings.Split(cryptoKeyVersion.Name, "cryptoKeys/")[1]
	}
	switch cryptoKeyVersion.Algorithm {
	case kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION:
		obj, err := backend.NewSecretKeyObject(generateID(cryptoKeyVersion.Name), cryptoKeyVersion.Name, true, true)
		if err != nil {
			return nil, err
		}
		return []backend.Object{obj}, nil
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
		privKey, err := cryptoKeyVersionToSigner(client, cryptoKeyVersion)
		if err != nil {
			return nil, err
		}
		privObject, err := backend.NewPrivateKeyObject(generateID(cryptoKeyVersion.Name), label, privKey, false, true, false)
		if err != nil {
			return nil, err
		}
		pubObject, err := backend.NewPublicKeyObject(generateID(cryptoKeyVersion.Name), label, privKey.Public(), true, false, false)
		if err != nil {
			return nil, err
		}
		return []backend.Object{privObject, pubObject}, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		privKey, err := cryptoKeyVersionToSigner(client, cryptoKeyVersion)
		if err != nil {
			return nil, err
		}

		privObject, err := backend.NewPrivateKeyObject(generateID(cryptoKeyVersion.Name), label, privKey, false, false, true)
		if err != nil {
			return nil, err
		}
		pubObject, err := backend.NewPublicKeyObject(generateID(cryptoKeyVersion.Name), label, privKey.Public(), false, false, true)
		if err != nil {
			return nil, err
		}

		// Create a fake certificate for GPG and Docker Content Trust
		cert, err := backend.GenerateStubCertificate(privKey)
		if err != nil {
			return nil, err
		}

		certObject, err := backend.NewCertificateObject(generateID(cryptoKeyVersion.Name), label, cert, true)
		if err != nil {
			return nil, err
		}

		return []backend.Object{privObject, pubObject, certObject}, nil
	}
	return nil, errors.New("unknown key version algorithm")
}

func cryptoKeyVersionToSigner(client *kms.KeyManagementClient, cryptoKeyVersion *kmspb.CryptoKeyVersion) (crypto.Signer, error) {
	return NewSigner(client, cryptoKeyVersion)
}

func signerToCertificate(priv crypto.Signer) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Google KMS",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
