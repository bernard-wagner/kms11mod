package kms11

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

const certPEM = `-----BEGIN CERTIFICATE-----
MIIEwDCCA6igAwIBAgIEUQAAADANBgkqhkiG9w0BAQsFADCBmjELMAkGA1UEBhMC
WkExHDAaBgNVBAoME0VudGVyc2VrdCAoUHR5KSBMdGQxODA2BgNVBAsML0VwaGVt
ZXJhbCBFbnRlcnNla3QgRGV2IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MTMwMQYD
VQQDDCpFcGhlbWVyYWwgRGV2IEVudGVyc2VrdCBSU0EtMjA0OCBlbUNlcnQgQ0Ew
HhcNMTkxMDIyMDk0NjMzWhcNMjQxMDIwMDk0NjMzWjCBpDELMAkGA1UEBhMCWkEx
HDAaBgNVBAoME0VudGVyc2VrdCAoUHR5KSBMdGQxODA2BgNVBAsML0VwaGVtZXJh
bCBFbnRlcnNla3QgRGV2IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MT0wOwYDVQQD
DDRFcGhlbWVyYWwgRGV2IEVudGVyc2VrdCBSU0EtMjA0OCBlbUNlcnQgaXNzdWlu
ZyBDQSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA09O25J2mWWFE
qvHt4kwXWgPRxJQ29GNyiSlz+sd9ybcVeTgGoRAXP3MuFSMydyFRBNCQACHvG2jM
ZhbnbfYBzTrZvN4i6HZ2VUughymsded/lewgBLaEPVUxeOuaUi1yHTdJ2JDHMR62
tS4nOykaxtsrnh6aUSF/jV3zC+YaxlgFgZRA4mIN57nDeV8B182FZnyh4xlFV3Sy
ghwQYYlH6inbGLurdmPvXDQqbSHGXR9tl85vXqb88Z0tAfdro0nD1kAZ82afmh0R
Hv+30bTVSsahwRfT5FO2if4r1CbjbUgC4TJqc8GcyJEVOtzGspmYfIRzFaZ24xwt
pYMZt7w1wQIDAQABo4IBADCB/TAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwIBBjBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vcm9vdGNhLWNybC5lbnRlcnNl
a3QuY29tL2Rldi1yc2EtMjA0OC1yb290LWNhLmNybDA9BgNVHSAENjA0MDIGA1Ud
IDArMCkGCCsGAQUFBwIBFh1odHRwczovL3d3dy5lbnRlcnNla3QuY29tL2NwczAf
BgNVHSMEGDAWgBTBT6GTaxTJepCJ0BZp0yndqY+kkzAdBgNVHQ4EFgQUyV26dDed
B2tZLyjocuDgolmTPYQwEAYKKwYBBAGCqlsBCAQCBQAwDQYJKoZIhvcNAQELBQAD
ggEBACiGckvMxFaF3dAOVBWKQXsrV641PFBz8Dw+UDy3AUhDXeta63EXvI7mCfOV
8Sy4Pk3Q1Ct08r+ik1hErebbXrTSxrMuVld4bFe++TyWeI2PnDs+O6XAPIBMhT4E
hDKh/E4peCD05gCNIlS0lHPi270mQPnvRHT1k2KzUv9iUBuXhl6n+bWRpvQW23/e
766pW2+ylA5JuVNCWsH9Q63Aa917mV0UtJaZpqzrqRpWpXt9khkT7hclcDsQt0Ms
YeHwsgKOBzhMvmixfUOOHGWWfjR3B2lJfe4gGn5jU26/IrzxDnTqsmlPMILBTjX9
9XrRad/nbkP4DtEqaQhzlfyv1cg=
-----END CERTIFICATE-----`

func TestBasic(t *testing.T) {

	block, _ := pem.Decode([]byte(certPEM))

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %+v", err)
	}

	obj, err := NewCertificateObject([]byte("test"), "test", []*x509.Certificate{cert}, false)
	require.NoError(t, err)

	attrs, err := Attributes(obj)
	require.NoError(t, err)
	require.NotNil(t, attrs)

	obj2, err := NewPublicKeyObject([]byte("test"), "test", cert.PublicKey, false, false, true)
	require.NoError(t, err)

	attrs, err = Attributes(obj2)
	require.NoError(t, err)

	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	require.NoError(t, err)

	obj3, err := NewPrivateKeyObject([]byte("test"), "test", key, false, false, true)
	require.NoError(t, err)

	attrs, err = Attributes(obj3)
	require.NoError(t, err)
}
