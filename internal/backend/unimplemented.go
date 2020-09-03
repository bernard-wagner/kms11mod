package backend
import (
	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
)

func (t *token) InitPIN(sh pkcs11.SessionHandle, pin string) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) SetPIN(sh pkcs11.SessionHandle, oldPin string, newPin string) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) CloseAllSessions(slotID uint) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) GetOperationState(sh pkcs11.SessionHandle) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) SetOperationState(sh pkcs11.SessionHandle, state []byte, encryptKey, authKey pkcs11.ObjectHandle) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) CreateObject(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	logrus.Trace()
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
func (t *token) CopyObject(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	logrus.Trace()
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) GetObjectSize(sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle) (uint, error) {
	logrus.Trace()
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DestroyObject(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) SetAttributeValue(sh pkcs11.SessionHandle, objectHandle pkcs11.ObjectHandle, attrs []*pkcs11.Attribute) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DigestInit(pkcs11.SessionHandle, []*pkcs11.Mechanism) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) Digest(pkcs11.SessionHandle, []byte) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DigestNull(pkcs11.SessionHandle, []byte) (int, error) {
	logrus.Trace()
	return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DigestUpdate(pkcs11.SessionHandle, []byte) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DigestKey(pkcs11.SessionHandle, pkcs11.ObjectHandle) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DigestFinal(pkcs11.SessionHandle) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) SignRecoverInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) SignRecover(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) VerifyInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
func (t *token) Verify(pkcs11.SessionHandle, []byte, []byte) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
func (t *token) VerifyUpdate(pkcs11.SessionHandle, []byte) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
func (t *token) VerifyFinal(pkcs11.SessionHandle, []byte) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
func (t *token) VerifyRecoverInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
func (t *token) VerifyRecover(pkcs11.SessionHandle, []byte) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DigestEncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DecryptDigestUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) SignEncryptUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DecryptVerifyUpdate(pkcs11.SessionHandle, []byte) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) GenerateKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	logrus.Trace()
	return pkcs11.ObjectHandle(0), pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) GenerateKeyPair(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	logrus.Trace()
	return pkcs11.ObjectHandle(0), pkcs11.ObjectHandle(0), pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) UnwrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []byte, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	logrus.Trace()
	return pkcs11.ObjectHandle(0), pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	logrus.Trace()
	return pkcs11.ObjectHandle(0), pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) SeedRandom(pkcs11.SessionHandle, []byte) error {
	logrus.Trace()
	return pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}

func (t *token) GenerateRandom(pkcs11.SessionHandle, int) ([]byte, error) {
	logrus.Trace()
	return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
}
