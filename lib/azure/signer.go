package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/bernard-wagner/kms11mod/internal/backend"
)

type keyVaultClient interface {
	GetKey(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string) (result keyvault.KeyBundle, err error)
	Sign(ctx context.Context, vaultBaseURL string, keyName string, keyVersion string, parameters keyvault.KeySignParameters) (result keyvault.KeyOperationResult, err error)
}

// privateKey contains a reference to a KMS private key.
type privateKey struct {
	client     keyVaultClient
	pubKey     crypto.PublicKey
	baseURI    string
	keyName    string
	keyVersion string
}

func (privKey *privateKey) Public() crypto.PublicKey {
	return privKey.pubKey
}

func NewSigner(client keyVaultClient, key keyvault.JSONWebKey) (crypto.Signer, error) {
	re := regexp.MustCompile("^(https://[^/]+)/keys/([^/]+)/([^/]+)$")
	parts := re.FindStringSubmatch(*key.Kid)
	if parts == nil || len(parts) < 2 {
		return nil, fmt.Errorf("azure: could not parse keyID, malformed string %q", *key.Kid)
	}

	baseURI := parts[1]
	keyName := parts[2]
	keyVersion := parts[3]

	var rawKey crypto.PublicKey
	var err error
	switch key.Kty {
	case keyvault.EC, keyvault.ECHSM:
		rawKey, err = convertJSONWebKeyToEcdsaPublicKey(key)
	case keyvault.RSA, keyvault.RSAHSM:
		rawKey, err = convertJSONWebKeyToRSAPublicKey(key)
	default:
		return nil, errors.New("azure: unknown key type")
	}
	if err != nil {
		return nil, err
	}

	privKey := &privateKey{
		client:     client,
		pubKey:     rawKey,
		baseURI:    baseURI,
		keyName:    keyName,
		keyVersion: keyVersion,
	}
	return privKey, nil
}

func (privKey *privateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signAlgo := keyvault.RSNULL
	pubKeyAlgorithm := backend.GetPublicKeyAlgorithm(privKey)

	for kvSigAlgo, sigAlgoDetails := range signatureAlgorithmProperties {
		if sigAlgoDetails.PubKeyAlgo == pubKeyAlgorithm && backend.SignatureAlgorithmDetails[sigAlgoDetails.SignatureAlgorithm].Hash == opts.HashFunc() {
			signAlgo = kvSigAlgo
			break
		}
	}
	if signAlgo == keyvault.RSNULL {
		return nil, errors.New("unsupported hashing algorithm")
	}

	resp, err := privKey.client.Sign(context.Background(), privKey.baseURI, privKey.keyName, privKey.keyVersion, keyvault.KeySignParameters{
		Value:     aws.String(base64.RawURLEncoding.EncodeToString(digest)),
		Algorithm: signAlgo,
	})
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(*resp.Result)
	if err != nil {
		return nil, errors.New("invalid response received")
	}

	return signature, nil
}
