package main

import (
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/bernard-wagner/kms11mod/kms11"
)

func convertKeyToObjects(client keyManagementClient, key *kms.GetPublicKeyOutput) ([]kms11.Object, error) {
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

	privObject, err := kms11.NewPrivateKeyObject([]byte(*key.KeyId), *key.KeyId, privKey, !decrypt, decrypt, sign)
	if err != nil {
		return nil, err
	}
	pubObject, err := kms11.NewPublicKeyObject([]byte(*key.KeyId), *key.KeyId, privKey.Public(), decrypt, !decrypt, sign)
	if err != nil {
		return nil, err
	}

	// Create a fake certificate for GPG and Docker Content Trust
	cert, err := kms11.GenerateStubCertificate(privKey)
	if err != nil {
		return nil, err
	}

	certObject, err := kms11.NewCertificateObject([]byte(*key.KeyId), *key.KeyId, cert, true)
	if err != nil {
		return nil, err
	}

	return []kms11.Object{privObject, pubObject, certObject}, nil
}
