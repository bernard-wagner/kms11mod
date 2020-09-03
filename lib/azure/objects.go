package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/bernard-wagner/kms11mod/internal/backend"
)

func convertJSONWebKeyToObject(client keyvault.BaseClient, key keyvault.JSONWebKey, addCert bool) ([]backend.Object, error) {
	privKey, err := NewSigner(client, key)
	if err != nil {
		return nil, err
	}

	sign := false
	decrypt := false
	encrypt := false
	for _, op := range *key.KeyOps {
		sign = sign || keyvault.JSONWebKeyOperation(op) == keyvault.Sign
		decrypt = decrypt || keyvault.JSONWebKeyOperation(op) == keyvault.Decrypt
		encrypt = encrypt || keyvault.JSONWebKeyOperation(op) == keyvault.Encrypt
	}

	privObject, err := backend.NewPrivateKeyObject([]byte(keyVersion(key)), *key.Kid, privKey, encrypt, decrypt, sign)
	if err != nil {
		return nil, err
	}

	pubObject, err := backend.NewPublicKeyObject([]byte(keyVersion(key)), *key.Kid, privKey.Public(), encrypt, decrypt, sign)
	if err != nil {
		return nil, err
	}

	var certObject backend.Object
	if addCert {
		// Create a fake certificate for GPG and Docker Content Trust
		cert, err := backend.GenerateStubCertificate(privKey)
		if err != nil {
			return nil, err
		}

		certObject, err = backend.NewCertificateObject([]byte(keyVersion(key)), *key.Kid, cert, true)
		if err != nil {
			return nil, err
		}
	}

	return []backend.Object{privObject, pubObject, certObject}, nil
}

func convertCertificateBundleToObject(client keyvault.BaseClient, bundle keyvault.CertificateBundle, key keyvault.JSONWebKey) ([]backend.Object, error) {
	block, _ := pem.Decode(*bundle.Cer)
	if block == nil {
		return nil, errors.New("azure: response does not contain valid pem data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	certObject, err := backend.NewCertificateObject([]byte(*bundle.ID), *bundle.ID, []*x509.Certificate{cert}, true)
	if err != nil {
		return nil, err
	}

	objs, err := convertJSONWebKeyToObject(client, key, false)
	if err != nil {
		return nil, err
	}

	return append(objs, certObject), nil
}

func convertJSONWebKeyToEcdsaPublicKey(key keyvault.JSONWebKey) (*ecdsa.PublicKey, error) {
	if (key.Kty != keyvault.EC && key.Kty != keyvault.ECHSM) ||
		(key.X == nil || key.Y == nil) {
		return nil, errors.New("azure: JSONWebKey does not contain an elliptic curve public key")
	}

	xb, err := base64.RawURLEncoding.DecodeString(*key.X)
	if err != nil {
		return nil, errors.New("azure: invalid ecc param: x")
	}

	x := new(big.Int).SetBytes(xb)
	yb, err := base64.RawURLEncoding.DecodeString(*key.Y)
	if err != nil {
		return nil, errors.New("azure: invalid ecc param: y")
	}

	y := new(big.Int).SetBytes(yb)
	var curve elliptic.Curve

	switch key.Crv {
	case keyvault.P256:
		curve = elliptic.P256()
	case keyvault.P384:
		curve = elliptic.P384()
	case keyvault.P521:
		curve = elliptic.P521()
	default:
		return nil, errors.New("azure: unknown curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func convertJSONWebKeyToRSAPublicKey(key keyvault.JSONWebKey) (*rsa.PublicKey, error) {
	if (key.Kty != keyvault.RSA && key.Kty != keyvault.RSAHSM) ||
		(key.N == nil || key.E == nil) {
		return nil, errors.New("auzre: JSONWebKey does not contain a RSA public key")
	}

	nStr := *key.N
	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, errors.New("azure: invalid rsa modulus")
	}
	n := new(big.Int).SetBytes(nb)
	eb, err := base64.RawURLEncoding.DecodeString(*key.E)
	if err != nil {
		return nil, errors.New("azure: invalid rsa exponent")
	}
	e := new(big.Int).SetBytes(eb)
	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
