package main

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/bernard-wagner/kms11mod/internal/backend"
)

func convertKeyToObjects(client keyManagementClient, key *kms.GetPublicKeyOutput) ([]backend.Object, error) {
	privKey, err := NewSigner(client, *key.KeyId)
	if err != nil {
		return nil, err
	}

	sign := false
	decrypt := false

	switch *key.KeyUsage {
	case kms.KeyUsageTypeSignVerify:
		sign = true
	case kms.KeyUsageTypeEncryptDecrypt:
		decrypt = true
	}

	privObject, err := backend.NewPrivateKeyObject([]byte(*key.KeyId), *key.KeyId, privKey, !decrypt, decrypt, sign)
	if err != nil {
		return nil, err
	}
	pubObject, err := backend.NewPublicKeyObject([]byte(*key.KeyId), *key.KeyId, privKey.Public(), decrypt, !decrypt, sign)
	if err != nil {
		return nil, err
	}

	// Create a fake certificate for GPG and Docker Content Trust
	cert, err := backend.GenerateStubCertificate(privKey)
	if err != nil {
		return nil, err
	}

	certObject, err := backend.NewCertificateObject([]byte(*key.KeyId), *key.KeyId, cert, true)
	if err != nil {
		return nil, err
	}

	return []backend.Object{privObject, pubObject, certObject}, nil
}
