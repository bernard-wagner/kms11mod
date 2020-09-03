package kms11

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"

	"github.com/miekg/pkcs11"
)

var attributeMap = map[string]uint{
	"CKA_CLASS":                pkcs11.CKA_CLASS,
	"CKA_LABEL":                pkcs11.CKA_LABEL,
	"CKA_ID":                   pkcs11.CKA_ID,
	"CKA_APPLICATION":          pkcs11.CKA_APPLICATION,
	"CKA_VALUE":                pkcs11.CKA_VALUE,
	"CKA_CERTIFICATE_TYPE":     pkcs11.CKA_CERTIFICATE_TYPE,
	"CKA_SERIAL_NUMBER":        pkcs11.CKA_SERIAL_NUMBER,
	"CKA_MODIFIABLE":           pkcs11.CKA_MODIFIABLE,
	"CKA_PRIVATE":              pkcs11.CKA_PRIVATE,
	"CKA_ISSUER":               pkcs11.CKA_ISSUER,
	"CKA_SUBJECT":              pkcs11.CKA_SUBJECT,
	"CKA_CERTIFICATE_CATEGORY": pkcs11.CKA_CERTIFICATE_CATEGORY,
	"CKA_KEY_TYPE":             pkcs11.CKA_KEY_TYPE,
	"CKA_MODULUS":              pkcs11.CKA_MODULUS,
	"CKA_MODULUS_BITS":         pkcs11.CKA_MODULUS_BITS,
	"CKA_WRAP":                 pkcs11.CKA_WRAP,
	"CKA_ENCRYPT":              pkcs11.CKA_ENCRYPT,
	"CKA_PUBLIC_EXPONENT":      pkcs11.CKA_PUBLIC_EXPONENT,
	"CKA_VERIFY":               pkcs11.CKA_VERIFY,
	"CKA_PRIME":                pkcs11.CKA_PRIME,
	"CKA_SUBPRIME":             pkcs11.CKA_SUBPRIME,
	"CKA_BASE":                 pkcs11.CKA_BASE,
	"CKA_DECRYPT":              pkcs11.CKA_DECRYPT,
	"CKA_SIGN":                 pkcs11.CKA_SIGN,
	"CKA_UNWRAP":               pkcs11.CKA_UNWRAP,
	"CKA_EXTRACTABLE":          pkcs11.CKA_EXTRACTABLE,
	"CKA_SENSITIVE":            pkcs11.CKA_SENSITIVE,
	"CKA_ALWAYS_AUTHENTICATE":  pkcs11.CKA_ALWAYS_AUTHENTICATE,
	"CKA_EC_POINT":             pkcs11.CKA_EC_POINT,
	"CKA_EC_PARAMS":            pkcs11.CKA_EC_PARAMS,
}

func Attributes(s interface{}) ([]*pkcs11.Attribute, error) {
	attrs := []*pkcs11.Attribute{}
	// ValueOf returns a Value representing the run-time data
	value := reflect.ValueOf(s)
	structType := reflect.TypeOf(s)
	structFieldMap, err := structFieldMap(structType)

	if err != nil {
		return nil, err
	}

	for _, structField := range structFieldMap {

		fieldValue := value.FieldByName(structField.FieldName)

		if structField.IsOmitEmpty {
			// omit encoding
			continue
		}

		if fieldValue.Kind() == reflect.Struct {
			if !structField.IsInline {
				continue
			}
			inlineAttrs, err := Attributes(fieldValue.Interface())
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, inlineAttrs...)
			continue
		}

		val, err := encodeValue(fieldValue)
		if err != nil {
			continue
		}

		attr, ok := attributeMap[structField.RenderName]
		if !ok {
			return nil, fmt.Errorf("unknown attribute type: %s", structField.RenderName)
		}

		attrs = append(attrs, pkcs11.NewAttribute(attr, val))
	}

	return attrs, nil
}

func attributeFilter(src []*pkcs11.Attribute, filters []*pkcs11.Attribute) (results []*pkcs11.Attribute) {
	m := make(map[uint]*pkcs11.Attribute)

	for _, item := range src {
		m[item.Type] = item
	}

	for _, f := range filters {
		if found, ok := m[f.Type]; ok {
			results = append(results, found)
		}
	}
	return
}

func attributeIntersection(src []*pkcs11.Attribute, filters []*pkcs11.Attribute) (results []*pkcs11.Attribute) {
	m := make(map[uint]*pkcs11.Attribute)

	for _, item := range src {
		m[item.Type] = item
	}

	for _, f := range filters {
		if found, ok := m[f.Type]; ok {
			if bytes.Equal(found.Value, f.Value) || (len(bytes.Trim(f.Value, "\x00")) == 0) {
				results = append(results, found)
			}
		}
	}
	return
}

func formatAttrs(attrs []*pkcs11.Attribute) (result map[string]interface{}) {
	if len(attrs) == 0 {
		return nil
	}

	result = make(map[string]interface{})
	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_ID:
			result["CKA_ID"] = hex.EncodeToString(attr.Value)

		case pkcs11.CKA_LABEL:
			result["CKA_LABEL"] = string(attr.Value)
		case pkcs11.CKA_CLASS:
			result["CKA_CLASS"] = attr.Value
		default:
			result[strconv.FormatUint(uint64(attr.Type), 16)+"UL"] = attr.Value
		}

	}
	return
}
