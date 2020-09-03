package kms11

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
)

type fakeSigner struct {
	privKey crypto.Signer
}

func (s *fakeSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, nil
}

func (s *fakeSigner) Public() crypto.PublicKey {
	return s.privKey.Public()
}

// GenerateStubCertificate is used to create invalid x509 certificate for
// GPG and Docker Content Trust. In order for GPG to detect a key using pkcs11-scd
// a certificate object has to exist. The same is true for Docker Content Trust's
// root key
func GenerateStubCertificate(privKey crypto.Signer) ([]*x509.Certificate, error) {
	fs := &fakeSigner{
		privKey: privKey,
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Root", // We use Root for Docker Content Trust
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, fs.Public(), fs)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return []*x509.Certificate{cert}, nil
}
