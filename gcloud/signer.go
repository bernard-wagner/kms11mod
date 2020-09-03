package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	gax "github.com/googleapis/gax-go/v2"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// keyManagementClient is a mockable interface for cloudkms.KeyManagementClient
type keyManagementClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
}

// privateKey contains a reference to a KMS private key.
type privateKey struct {
	cryptoKeyVersion *kmspb.CryptoKeyVersion
	client           keyManagementClient
	pubKey           crypto.PublicKey
}

func NewSigner(client keyManagementClient, cryptoKeyVersion *kmspb.CryptoKeyVersion) (crypto.Signer, error) {

	privKey := &privateKey{cryptoKeyVersion: cryptoKeyVersion, client: client}

	// Fetch the public key
	if err := privKey.loadPublicKey(); err != nil {
		return nil, err
	}

	return privKey, nil
}

func (privKey *privateKey) loadPublicKey() error {
	ctx := context.Background()
	req := &kmspb.GetPublicKeyRequest{Name: privKey.cryptoKeyVersion.Name}

	// Call the API.
	response, err := privKey.client.GetPublicKey(ctx, req)
	if err != nil {
		return err
	}
	// Parse the key.
	keyBytes := []byte(response.Pem)
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return errors.New("public key not valid PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	privKey.pubKey = publicKey
	return nil
}

func (privKey *privateKey) Public() crypto.PublicKey {
	return privKey.pubKey
}

// Represents the two mathematical components of an ECDSA signature once
// decomposed.
type ECDSASignature struct {
	R, S *big.Int
}

func (privKey *privateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()

	digestFunc, ok := cryptoHashDigests[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm")
	}

	// Build the signing request.
	req := &kmspb.AsymmetricSignRequest{
		Name:   privKey.cryptoKeyVersion.Name,
		Digest: digestFunc(digest),
	}

	// Call the API.
	response, err := privKey.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("asymmetric sign request failed: %+v", err)
	}

	result := response.Signature
	switch privKey.Public().(type) {
	case *ecdsa.PublicKey:
		sig := &ECDSASignature{}
		asn1.Unmarshal(result, sig)
		result = append(sig.R.Bytes(), sig.S.Bytes()...)
	}
	return result, nil
}
