package kms11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

type objectClass uint

const (
	ObjectClassData        = objectClass(pkcs11.CKO_DATA)
	ObjectClassCertificate = objectClass(pkcs11.CKO_CERTIFICATE)
	ObjectClassPublicKey   = objectClass(pkcs11.CKO_PUBLIC_KEY)
	ObjectClassPrivateKey  = objectClass(pkcs11.CKO_PRIVATE_KEY)
	ObjectClassSecretKey   = objectClass(pkcs11.CKO_SECRET_KEY)
)

type certificateType uint

const (
	CertificateTypeX509 = certificateType(pkcs11.CKC_X_509)
)

type certificateCategory uint

const (
	CertificateCategoryUnspecified = certificateCategory(0)
	CertificateCategoryTokenUser   = certificateCategory(1)
	CertificateCategoryAuthority   = certificateCategory(2)
	CertificateCategoryEntity      = certificateCategory(3)
)

type keyType uint

const (
	KeyTypeRSA   = keyType(pkcs11.CKK_RSA)
	KeyTypeECDSA = keyType(pkcs11.CKK_ECDSA)
)

func GetInner(o interface{}) interface{} {
	switch t := o.(type) {
	case CertificateObject:
		return t.chain
	case RSAPublicKeyObject:
		return t.publicKey
	case ECPublicKeyObject:
		return t.publicKey
	case RSAPrivateKeyObject:
		return t.signer
	case ECPrivateKeyObject:
		return t.signer
	}

	return nil
}

type DataObject struct {
	ObjectClass objectClass `pkcs11:"CKA_CLASS"`
	Label       string      `pkcs11:"CKA_LABEL"`
	ID          []byte      `pkcs11:"CKA_ID"`
	Application string      `pkcs11:"CKA_APPLICATION"`
	Private     bool        `pkcs11:"CKA_PRIVATE"`
	Modifiable  bool        `pkcs11:"CKA_MODIFIABLE"`
}

type CertificateObject struct {
	DataObject `pkcs11:",inline"`
	CertType   certificateType     `pkcs11:"CKA_CERTIFICATE_TYPE"`
	Subject    []byte              `pkcs11:"CKA_SUBJECT"`
	Issuer     []byte              `pkcs11:"CKA_ISSUER"`
	Serial     int64               `pkcs11:"CKA_SERIAL_NUMBER"`
	Category   certificateCategory `pkcs11:"CKA_CERTIFICATE_CATEGORY"`
	Value      []byte              `pkcs11:"CKA_VALUE"`
	chain      []*x509.Certificate
}

type PublicKeyObject struct {
	Subject []byte  `pkcs11:"CKA_SUBJECT"`
	KeyType keyType `pkcs11:"CKA_KEY_TYPE"`
	Wrap    bool    `pkcs11:"CKA_WRAP"`
	Encrypt bool    `pkcs11:"CKA_ENCRYPT"`
	Decrypt bool    `pkcs11:"CKA_DECRYPT"`
	Verify  bool    `pkcs11:"CKA_VERIFY"`
}

type RSAPublicKeyObject struct {
	DataObject      `pkcs11:",inline"`
	PublicKeyObject `pkcs11:",inline"`
	Modulus         []byte `pkcs11:"CKA_MODULUS"`
	ModulusBits     int    `pkcs11:"CKA_MODULUS_BITS"`
	PublicExponent  []byte `pkcs11:"CKA_PUBLIC_EXPONENT"`
	publicKey       *rsa.PublicKey
}

type ECPublicKeyObject struct {
	DataObject      `pkcs11:",inline"`
	PublicKeyObject `pkcs11:",inline"`
	Prime           []byte `pkcs11:"CKA_PRIME"`
	SubPrime        []byte `pkcs11:"CKA_SUBPRIME"`
	Base            []byte `pkcs11:"CKA_BASE"`
	EcParams        []byte `pkcs11:"CKA_EC_PARAMS"`
	EcPoint         []byte `pkcs11:"CKA_EC_POINT"`
	publicKey       *ecdsa.PublicKey
}

type SecretKeyObject struct {
	DataObject         `pkcs11:",inline"`
	Sensitive          bool `pkcs11:"CKA_SENSITIVE"`
	Decrypt            bool `pkcs11:"CKA_DECRYPT"`
	Sign               bool `pkcs11:"CKA_SIGN"`
	Encrypt            bool `pkcs11:"CKA_ENCRYPT"`
	Unwrap             bool `pkcs11:"CKA_UNWRAP"`
	Extractable        bool `pkcs11:"CKA_EXTRACTABLE"`
	AlwaysAuthenticate bool `pkcs11:"CKA_ALWAYS_AUTHENTICATE"`
}

type RSAPrivateKeyObject struct {
	SecretKeyObject    `pkcs11:",inline"`
	RSAPublicKeyObject `pkcs11:",inline"`
	signer             crypto.Signer
}

type ECPrivateKeyObject struct {
	SecretKeyObject   `pkcs11:",inline"`
	ECPublicKeyObject `pkcs11:",inline"`
	signer            crypto.Signer
}

func NewCertificateObject(id []byte, label string, chain []*x509.Certificate, hasKey bool) (Object, error) {
	if len(chain) < 1 {
		return nil, fmt.Errorf("kms11: chain must contain at least one certificate")
	}

	serial := chain[0].SerialNumber.Int64()
	issuer := chain[0].RawIssuer
	subject := chain[0].RawSubject
	value := chain[0].Raw

	category := CertificateCategoryTokenUser

	if !hasKey {
		category = CertificateCategoryEntity
	}

	if chain[0].IsCA {
		category = CertificateCategoryAuthority
	}

	return CertificateObject{
		DataObject: DataObject{
			ObjectClass: ObjectClassCertificate,
			ID:          id,
			Label:       label,
			Private:     false,
			Modifiable:  false,
		},
		Value:    value,
		Serial:   serial,
		CertType: CertificateTypeX509,
		Subject:  subject,
		Issuer:   issuer,
		Category: category,
		chain:    chain,
	}, nil
}

func NewPublicKeyObject(id []byte, label string, pub crypto.PublicKey, encrypt bool, decrypt bool, verify bool) (Object, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return NewRSAPublicKeyObject(id, label, pub, encrypt, decrypt, verify)
	case *ecdsa.PublicKey:
		return NewECPublicKeyObject(id, label, pub, encrypt, decrypt, verify)
	}

	return nil, errors.New("unknown key type")
}

func NewRSAPublicKeyObject(id []byte, label string, pub *rsa.PublicKey, encrypt bool, decrypt bool, verify bool) (RSAPublicKeyObject, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(pub.E))
	return RSAPublicKeyObject{
		publicKey: pub,
		PublicKeyObject: PublicKeyObject{
			KeyType: KeyTypeRSA,
			Decrypt: decrypt,
			Encrypt: encrypt,
			Verify:  verify,
		},
		DataObject: DataObject{
			ObjectClass: ObjectClassPublicKey,
			ID:          id,
			Label:       label,
			Private:     false,
			Modifiable:  false,
		},
		PublicExponent: b,
		Modulus:        pub.N.Bytes(),
		ModulusBits:    pub.Size() * 8,
	}, nil
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var curveOIDs = map[string]asn1.ObjectIdentifier{
	"P-224": oidNamedCurveP224,
	"P-256": oidNamedCurveP256,
	"P-384": oidNamedCurveP384,
	"P-521": oidNamedCurveP521,
}

func NewECPublicKeyObject(id []byte, label string, pub *ecdsa.PublicKey, encrypt bool, decrypt bool, verify bool) (ECPublicKeyObject, error) {
	rawValue := asn1.RawValue{
		Tag:   4, // in Go 1.6+ this is asn1.TagOctetString
		Bytes: elliptic.Marshal(pub.Curve, pub.X, pub.Y),
	}
	marshalledPoint, err := asn1.Marshal(rawValue)
	if err != nil {
		return ECPublicKeyObject{}, err
	}

	curveOID, err := asn1.Marshal(curveOIDs[pub.Curve.Params().Name])
	if err != nil {
		return ECPublicKeyObject{}, err
	}

	return ECPublicKeyObject{
		EcPoint:   marshalledPoint,
		EcParams:  curveOID,
		publicKey: pub,
		PublicKeyObject: PublicKeyObject{
			KeyType: KeyTypeECDSA,
			Decrypt: decrypt,
			Encrypt: encrypt,
			Verify:  verify,
		},
		DataObject: DataObject{
			ObjectClass: ObjectClassPublicKey,
			ID:          id,
			Label:       label,
			Private:     false,
			Modifiable:  false,
		},
	}, nil
}

func NewPrivateKeyObject(id []byte, label string, priv crypto.Signer, encrypt bool, decrypt bool, sign bool) (Object, error) {
	switch priv.Public().(type) {
	case *rsa.PublicKey:
		return NewRSAPrivateKeyObject(id, label, priv, encrypt, decrypt, sign)
	case *ecdsa.PublicKey:
		return NewECPrivateKeyObject(id, label, priv, encrypt, decrypt, sign)
	}

	return nil, nil
}

func NewRSAPrivateKeyObject(id []byte, label string, priv crypto.Signer, encrypt bool, decrypt bool, sign bool) (Object, error) {
	pubObject, err := NewRSAPublicKeyObject(id, label, priv.Public().(*rsa.PublicKey), encrypt, decrypt, sign)
	if err != nil {
		return nil, err
	}

	pubObject.DataObject = DataObject{
		ObjectClass: ObjectClassPrivateKey,
		ID:          id,
		Label:       label,
		Private:     false,
		Modifiable:  false,
	}
	return RSAPrivateKeyObject{
		signer:             priv,
		RSAPublicKeyObject: pubObject,
		SecretKeyObject: SecretKeyObject{
			Sensitive:   true,
			Extractable: false,
			Decrypt:     decrypt,
			Sign:        sign,
			Unwrap:      false,
			DataObject:  pubObject.DataObject,
		},
	}, nil
}

func NewECPrivateKeyObject(id []byte, label string, priv crypto.Signer, encrypt bool, decrypt bool, sign bool) (Object, error) {
	pubObject, err := NewECPublicKeyObject(id, label, priv.Public().(*ecdsa.PublicKey), encrypt, decrypt, sign)
	if err != nil {
		return nil, err
	}
	pubObject.DataObject = DataObject{
		ObjectClass: ObjectClassPrivateKey,
		ID:          id,
		Label:       label,
		Private:     false,
		Modifiable:  false,
	}
	return ECPrivateKeyObject{
		signer:            priv,
		ECPublicKeyObject: pubObject,
		SecretKeyObject: SecretKeyObject{
			Sensitive:   true,
			Extractable: false,
			Decrypt:     decrypt,
			Encrypt:     encrypt,
			Sign:        sign,
			Unwrap:      false,
			DataObject:  pubObject.DataObject,
		},
	}, nil
}

func NewSecretKeyObject(id []byte, label string, encrypt bool, decrypt bool) (Object, error) {
	return SecretKeyObject{
		DataObject: DataObject{
			ObjectClass: ObjectClassSecretKey,
			ID:          id,
			Label:       label,
			Private:     false,
			Modifiable:  false,
		},
		Sensitive:   true,
		Extractable: false,
		Decrypt:     decrypt,
		Encrypt:     encrypt,
		Sign:        false,
		Unwrap:      false,
	}, nil
}

func (k RSAPrivateKeyObject) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.signer.Sign(rand, digest, opts)
}

func (k ECPrivateKeyObject) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return k.signer.Sign(rand, digest, opts)
}

func (k RSAPrivateKeyObject) Public() crypto.PublicKey {
	return k.signer.Public()
}

func (k ECPrivateKeyObject) Public() crypto.PublicKey {
	return k.signer.Public()
}
