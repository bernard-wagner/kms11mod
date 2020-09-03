package backend
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"time"

	"github.com/bernard-wagner/kms11mod/pkcs11mod"
	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
)

type Object interface{}

type Iterator interface {
	Next() (Object, error)
}

type Backend interface {
	FindObjectsInit() (Iterator, error)
}

type token struct {
	sync.Mutex
	backend  Backend
	sessions map[pkcs11.SessionHandle]*session
}

func NewToken(backend Backend) pkcs11mod.Backend {
	return &token{
		backend:  backend,
		sessions: make(map[pkcs11.SessionHandle]*session),
	}
}

type session struct {
	sync.Mutex
	slotID    uint
	find      *findOperation
	operation *operation
	objects   map[pkcs11.ObjectHandle]Object
}

type operation struct {
	data      []byte
	object    Object
	mechanism *pkcs11.Mechanism
}

type findOperation struct {
	attrs []*pkcs11.Attribute
	iter  Iterator
}

func (t *token) GetSession(sh pkcs11.SessionHandle) (*session, error) {
	t.Lock()
	defer t.Unlock()
	s, ok := t.sessions[sh]
	if !ok {
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	return s, nil

}

func (t *token) Initialize() error {
	logrus.Trace()
	return nil
}

func (t *token) Finalize() error {
	logrus.Trace()
	logrus.WithFields(logrus.Fields{"rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) GetInfo() (pkcs11.Info, error) {
	logrus.Trace()

	result := pkcs11.Info{
		CryptokiVersion:    pkcs11.Version{Major: byte(2), Minor: byte(40)},
		ManufacturerID:     "kms11",
		LibraryDescription: "kms11",
		LibraryVersion:     pkcs11.Version{Major: byte(2), Minor: byte(40)},
	}

	logrus.WithFields(logrus.Fields{"result": result, "rv": "CKR_OK"}).Trace()
	return result, nil
}

func (t *token) GetSlotList(bool) ([]uint, error) {
	logrus.Trace()

	slots := []uint{0}

	logrus.WithFields(logrus.Fields{"slots": slots, "rv": "CKR_OK"}).Trace()
	return slots, nil
}

func (t *token) GetSlotInfo(_ uint) (pkcs11.SlotInfo, error) {
	logrus.WithFields(logrus.Fields{}).Trace()

	result := pkcs11.SlotInfo{
		SlotDescription: "kms11",
		ManufacturerID:  "kms11",
		Flags:           pkcs11.CKF_TOKEN_PRESENT | pkcs11.CKF_LOGIN_REQUIRED,
	}

	logrus.WithFields(logrus.Fields{"result": result, "rv": "CKR_OK"}).Trace()
	return result, nil
}

func (t *token) GetTokenInfo(_ uint) (pkcs11.TokenInfo, error) {
	logrus.Trace()
	result := pkcs11.TokenInfo{
		Label:              "kms11",
		ManufacturerID:     "kms11",
		Model:              "kms11",
		SerialNumber:       "",
		UTCTime:            time.Now().String(),
		SessionCount:       pkcs11.CK_UNAVAILABLE_INFORMATION,
		RwSessionCount:     pkcs11.CK_UNAVAILABLE_INFORMATION,
		MaxSessionCount:    pkcs11.CK_EFFECTIVELY_INFINITE,
		MaxRwSessionCount:  pkcs11.CK_EFFECTIVELY_INFINITE,
		Flags:              pkcs11.CKF_TOKEN_INITIALIZED | pkcs11.CKF_USER_PIN_INITIALIZED | pkcs11.CKF_LOGIN_REQUIRED,
		HardwareVersion:    pkcs11.Version{Major: byte(1), Minor: byte(0)},
		FirmwareVersion:    pkcs11.Version{Major: byte(1), Minor: byte(0)},
		TotalPublicMemory:  pkcs11.CK_UNAVAILABLE_INFORMATION,
		FreePublicMemory:   pkcs11.CK_UNAVAILABLE_INFORMATION,
		TotalPrivateMemory: pkcs11.CK_UNAVAILABLE_INFORMATION,
		FreePrivateMemory:  pkcs11.CK_UNAVAILABLE_INFORMATION,
	}

	logrus.WithFields(logrus.Fields{"result": result, "rv": "CKR_OK"}).Trace()
	return result, nil
}

func (t *token) GetMechanismList(_ uint) ([]*pkcs11.Mechanism, error) {
	logrus.Trace()

	results := []*pkcs11.Mechanism{}

	for _, m := range []uint{pkcs11.CKM_RSA_PKCS,
		pkcs11.CKM_SHA256_RSA_PKCS,
		pkcs11.CKM_SHA512_RSA_PKCS,
		pkcs11.CKM_RSA_PKCS_PSS,
		pkcs11.CKM_SHA256_RSA_PKCS_PSS,
		pkcs11.CKM_SHA512_RSA_PKCS_PSS,
		pkcs11.CKM_ECDSA_SHA256,
		pkcs11.CKM_ECDSA_SHA384,
		pkcs11.CKM_SHA384,
	} {
		results = append(results, &pkcs11.Mechanism{Mechanism: m})
	}

	logrus.WithFields(logrus.Fields{"results": results, "rv": "CKR_OK"}).Trace()
	return results, nil
}

func (t *token) GetMechanismInfo(_ uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error) {
	logrus.WithFields(logrus.Fields{"m": m}).Trace()

	if len(m) < 1 {
		logrus.WithFields(logrus.Fields{"m": m, "rv": "CKR_ARGUMENTS_BAD"}).Trace()
		return pkcs11.MechanismInfo{}, pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}

	result := pkcs11.MechanismInfo{}
	// if err != nil {
	// 	logrus.WithError(err).WithFields(logrus.Fields{"rv": "CKR_FUNCTION_FAILED"}).Error("GetMechanismInfo: failed to perform operation")
	// 	return pkcs11.MechanismInfo{}, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	// }

	logrus.WithFields(logrus.Fields{"result": result, "rv": "CKR_OK"}).Trace()
	return result, nil
}

func (t *token) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	logrus.WithFields(logrus.Fields{"slotID": slotID, "flags": flags}).Trace()

	t.Lock()
	defer t.Unlock()

	sh := pkcs11.SessionHandle(len(t.sessions))
	t.sessions[sh] = &session{slotID: slotID, objects: make(map[pkcs11.ObjectHandle]Object)}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return sh, nil
}

func (t *token) CloseSession(sh pkcs11.SessionHandle) error {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	t.Lock()
	defer t.Unlock()

	_, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}
	t.sessions[sh] = nil

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) GetSessionInfo(sh pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	t.Lock()
	defer t.Unlock()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.SessionInfo{}, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()

	return pkcs11.SessionInfo{
		SlotID: s.slotID,
		Flags:  pkcs11.CKF_RW_SESSION,
		State:  3,
	}, nil
}

func (t *token) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	logrus.WithFields(logrus.Fields{"sh": sh, "userType": userType, "pin": len(pin) > 0}).Trace()
	return nil
}

func (t *token) Logout(sh pkcs11.SessionHandle) error {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()
	return nil
}

func (t *token) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, attrs []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	logrus.WithFields(logrus.Fields{"sh": sh, "o": o, "attrs": formatAttrs(attrs)}).Trace()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	obj, ok := s.objects[o]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OBJECT_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	attrsObj, err := Attributes(obj)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	results := attributeFilter(attrsObj, attrs)

	logrus.WithFields(logrus.Fields{"sh": sh, "results": formatAttrs(results), "rv": "CKR_OK"}).Trace()
	return results, nil
}

func (t *token) FindObjectsInit(sh pkcs11.SessionHandle, attrs []*pkcs11.Attribute) error {
	logrus.WithFields(logrus.Fields{"sh": sh, "attrs": formatAttrs(attrs)}).Trace()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.find != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_ACTIVE"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)
	}

	iter, err := t.backend.FindObjectsInit()
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
		return pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	s.find = &findOperation{
		attrs: attrs,
		iter:  iter,
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	logrus.WithFields(logrus.Fields{"sh": sh, "max": max}).Trace()

	objs := make([]pkcs11.ObjectHandle, 0)

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, false, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.find == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return nil, false, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	for {
		if len(objs) >= max {
			break
		}

		obj, err := s.find.iter.Next()
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
			return nil, false, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
		}

		if obj == nil {
			logrus.Trace("iterator is done")
			break
		}

		attrsObj, err := Attributes(obj)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
			return nil, false, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
		}

		if len(s.find.attrs) == len(attributeIntersection(attrsObj, s.find.attrs)) {
			idx := pkcs11.ObjectHandle(len(s.objects))
			s.objects[idx] = obj
			objs = append(objs, idx)
		}
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "max": max, "objs": objs, "rv": "CKR_OK"}).Trace()
	return objs, false, nil
}

func (t *token) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	defer func() { s.find = nil }()

	if s.find == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) EncryptInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	logrus.WithFields(logrus.Fields{"sh": sh, "m": m, "o": o}).Trace()

	t.Lock()
	defer t.Unlock()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "m": m, "o": o, "rv": "CKR_OPERATION_ACTIVE"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)
	}

	if len(m) < 1 {
		logrus.WithFields(logrus.Fields{"sh": sh, "m": m, "o": o, "rv": "CKR_ARGUMENTS_BAD"}).Trace()
		return pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}

	obj, ok := s.objects[o]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OBJECT_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	//if !obj.IsSupportedMechanism(m[0]) {
	//	logrus.WithFields(logrus.Fields{"sh": sh, "m": m, "o": o, "rv": "CKR_MECHANISM_INVALID"}).Trace()
	//	return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	//}

	s.operation = &operation{object: obj, mechanism: m[0]}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) Encrypt(sh pkcs11.SessionHandle, data []byte) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh, "data": data}).Trace()

	if _, err := t.EncryptUpdate(sh, data); err != nil {
		return nil, err
	}

	return t.EncryptFinal(sh)
}

func (t *token) EncryptNull(sh pkcs11.SessionHandle, data []byte) (int, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return 0, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return 0, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	size := 0
	switch s.operation.mechanism.Mechanism {
	case pkcs11.CKM_AES_GCM:
		size = (len(data) + 31) / 32 * 32 //Nearest multiple of 32.
	case pkcs11.CKM_RSA_PKCS_OAEP:
		size = 2048
	default:
		logrus.WithFields(logrus.Fields{"sh": sh, "m": s.operation.mechanism.Mechanism, "rv": "CKR_FUNCTION_FAILED"}).Error("unknown mechansism")
		return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return size, nil
}

func (t *token) EncryptUpdate(sh pkcs11.SessionHandle, data []byte) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	s.operation.data = append(s.operation.data, data...)

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil, nil
}

func (t *token) EncryptFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	defer func() { s.operation = nil }()

	if s.operation == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_MECHANISM_INVALID"}).Trace()
	return nil, pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
}

func (t *token) DecryptInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, err := t.GetSession(sh)
	if err != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_ACTIVE"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)
	}

	if len(m) < 1 {
		logrus.WithFields(logrus.Fields{"sh": sh, "m": m, "rv": "CKR_ARGUMENTS_BAD"}).Trace()
		return pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}

	obj, ok := s.objects[o]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OBJECT_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	// if !obj.IsSupportedMechanism(m[0]) {
	// 	logrus.WithFields(logrus.Fields{"sh": sh, "m": m, "rv": "CKR_MECHANISM_INVALID"}).Trace()
	// 	return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	// }

	s.operation = &operation{object: obj, mechanism: m[0]}
	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) Decrypt(sh pkcs11.SessionHandle, data []byte) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	if _, err := t.DecryptUpdate(sh, data); err != nil {
		return nil, err
	}

	return t.DecryptFinal(sh)
}

func (t *token) DecryptNull(sh pkcs11.SessionHandle, data []byte) (int, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return 0, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return 0, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	size := 0
	switch s.operation.mechanism.Mechanism {
	case pkcs11.CKM_AES_GCM:
		size = (len(data) + 31) / 32 * 32 //Nearest multiple of 32.
	case pkcs11.CKM_RSA_PKCS_OAEP:
		size = 2048
	default:
		logrus.WithFields(logrus.Fields{"sh": sh, "m": s.operation.mechanism.Mechanism, "rv": "CKR_FUNCTION_FAILED"}).Error("unknown mechansism")
		return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "size": size, "rv": "CKR_OK"}).Trace()
	return size, nil
}

func (t *token) DecryptUpdate(sh pkcs11.SessionHandle, data []byte) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	s.operation.data = append(s.operation.data, data...)

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil, nil
}

func (t *token) DecryptFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	defer func() { s.operation = nil }()

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil, nil
}

func (t *token) SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	logrus.WithFields(logrus.Fields{"sh": sh, "m": m[0].Mechanism, "o": o}).Trace()

	t.Lock()
	defer t.Unlock()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation != nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_ACTIVE"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)
	}

	if len(m) < 1 {
		logrus.WithFields(logrus.Fields{"sh": sh, "m": m, "rv": "CKR_ARGUMENTS_BAD"}).Trace()
		return pkcs11.Error(pkcs11.CKR_ARGUMENTS_BAD)
	}

	obj, ok := s.objects[o]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OBJECT_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	// if !obj.IsSupportedMechanism(m[0]) {
	// 	logrus.WithFields(logrus.Fields{"sh": sh, "m": m[0].Mechanism, "rv": "CKR_MECHANISM_INVALID"}).Trace()
	// 	return pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
	// }

	s.operation = &operation{object: obj, mechanism: m[0]}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh, "msgLen": len(message)}).Trace()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	defer func() { s.operation = nil }()

	// Make sure we have a private key
	var priv crypto.Signer
	switch t := s.operation.object.(type) {
	case crypto.Signer:
		priv = t
	default:
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	var hash crypto.Hash
	switch s.operation.mechanism.Mechanism {
	case pkcs11.CKM_RSA_PKCS, pkcs11.CKM_ECDSA: // Pre-hashed

		// First see if PKCS1 padding has been done to determine
		// hash algorithm that was used
		for h, prefix := range hashPrefixes {
			if bytes.HasPrefix(message, prefix) {
				message = bytes.TrimPrefix(message, prefix)
				hash = h
				break
			}
		}

		// If no prefix was found we assume the hash algorithm
		// based on the message length
		if hash == crypto.Hash(0) {
			switch len(message) {
			case crypto.SHA256.HashFunc().Size():
				hash = crypto.SHA256
			case crypto.SHA384.HashFunc().Size():
				hash = crypto.SHA384
			case crypto.SHA512.HashFunc().Size():
				hash = crypto.SHA512
			}
		}
	default:
		switch s.operation.mechanism.Mechanism {
		case pkcs11.CKM_SHA256_RSA_PKCS, pkcs11.CKM_ECDSA_SHA256:
			hash = crypto.SHA256
		case pkcs11.CKM_SHA384_RSA_PKCS, pkcs11.CKM_ECDSA_SHA384:
			hash = crypto.SHA384
		case pkcs11.CKM_SHA512_RSA_PKCS, pkcs11.CKM_ECDSA_SHA512:
			hash = crypto.SHA512
		}

		// Hash the message
		hasher := hash.New()
		_, err := hasher.Write(message)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
			return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
		}
		message = hasher.Sum(nil)
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "hash": hash, "msgLen": len(message)}).Trace()

	signature, err := priv.Sign(rand.Reader, message, hash)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK", "signatureLen": len(signature)}).Trace()
	return signature, nil
}

func (t *token) SignNull(sh pkcs11.SessionHandle, message []byte) (int, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return 0, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	if s.operation == nil {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OPERATION_NOT_INITIALIZED"}).Trace()
		return 0, pkcs11.Error(pkcs11.CKR_OPERATION_NOT_INITIALIZED)
	}

	// Make sure we have a private key
	var priv crypto.Signer
	switch t := s.operation.object.(type) {
	case crypto.Signer:
		priv = t
	default:
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_FUNCTION_FAILED"}).Trace()
		return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	keysize := 0
	switch pub := priv.Public().(type) {
	case *rsa.PublicKey:
		keysize = pub.Size() * 8
	case ecdsa.PublicKey:
		keysize = pub.Params().BitSize
	default:
		logrus.WithFields(logrus.Fields{"sh": sh, "m": s.operation.mechanism.Mechanism, "rv": "CKR_FUNCTION_FAILED"}).Error("Unknown public key type")
		return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
	}

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return keysize, nil
}

func (t *token) SignUpdate(sh pkcs11.SessionHandle, message []byte) error {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	s.Lock()
	defer s.Unlock()

	s.operation.data = append(s.operation.data, message...)

	logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_OK"}).Trace()
	return nil
}

func (t *token) SignFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"sh": sh}).Trace()

	s, ok := t.sessions[sh]
	if !ok {
		logrus.WithFields(logrus.Fields{"sh": sh, "rv": "CKR_SESSION_HANDLE_INVALID"}).Trace()
		return nil, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	}

	return t.Sign(sh, s.operation.data)
}

func (t *token) WaitForSlotEvent(flags uint) chan pkcs11.SlotEvent {
	logrus.WithFields(logrus.Fields{"flags": flags}).Trace()

	sl := make(chan pkcs11.SlotEvent, 1) // hold one element
	return sl
}
