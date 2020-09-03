package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/bernard-wagner/kms11mod/kms11"
)

// keyManagementClient is a mockable interface for cloudkms.KeyManagementClient
type keyManagementClient interface {
	SignWithContext(ctx context.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error)
	GetPublicKeyWithContext(ctx context.Context, input *kms.GetPublicKeyInput, opts ...request.Option) (*kms.GetPublicKeyOutput, error)
}

// privateKey contains a reference to a KMS private key.
type privateKey struct {
	keyid  string
	client keyManagementClient
	pubKey crypto.PublicKey
}

func NewSigner(client keyManagementClient, keyID string) (crypto.Signer, error) {

	privKey := &privateKey{keyid: keyID, client: client}

	// Fetch the public key
	if err := privKey.loadPublicKey(); err != nil {
		return nil, err
	}

	return privKey, nil
}

func (privKey *privateKey) loadPublicKey() error {
	ctx := context.Background()
	req := &kms.GetPublicKeyInput{
		KeyId: aws.String(privKey.keyid),
	}

	// Call the API.
	response, err := privKey.client.GetPublicKeyWithContext(ctx, req)
	if err != nil {
		return err
	}

	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return err
	}

	privKey.pubKey = publicKey
	return nil
}

func (privKey *privateKey) Public() crypto.PublicKey {
	return privKey.pubKey
}

func (privKey *privateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()

	pubKeyType := kms11.GetPublicKeyAlgorithm(privKey)
	signAlgo := x509.UnknownSignatureAlgorithm

	// Determine the signature algorithm using the hash function and key type. Exclude
	// RSAPSS algorithms
	for algo, details := range kms11.SignatureAlgorithmDetails {
		if details.PubKeyAlgo == pubKeyType && details.Hash == opts.HashFunc() && !kms11.IsRSAPSS(algo) {
			signAlgo = algo
			break
		}
	}

	var kmsSigAlgo string
	for n, k := range kmsSignatureAlgorithmProperties {
		if k.SignatureAlgorithm == signAlgo {
			kmsSigAlgo = n
			break
		}
	}

	response, err := privKey.client.SignWithContext(ctx, &kms.SignInput{
		KeyId:            aws.String(privKey.keyid),
		SigningAlgorithm: aws.String(kmsSigAlgo),
		Message:          digest,
		MessageType:      aws.String(kms.MessageTypeDigest), //Already hashed
	})
	if err != nil {
		return nil, fmt.Errorf("asymmetric sign request failed: %+v", err)
	}

	// AWS returns the signature in DER encoded format, we need to
	// return it in OpenSSL format
	return kms11.FormatSignature(privKey, response.Signature), nil
}
