package kms11

import (
	"fmt"
	"reflect"
	"strings"
)

const (
	// StructTagName tag keyword for Marshal/Unmarshal
	StructTagName = "pkcs11"
)

// StructField information for each the field in structure
type StructField struct {
	FieldName   string
	RenderName  string
	IsOmitEmpty bool
	IsInline    bool
}

func getTag(field reflect.StructField) string {
	// If struct tag `yaml` exist, use that. If no `yaml`
	// exists, but `json` does, use that and try the best to
	// adhere to its rules
	tag := field.Tag.Get(StructTagName)

	return tag
}

func structField(field reflect.StructField) *StructField {
	tag := getTag(field)
	fieldName := strings.ToLower(field.Name)
	options := strings.Split(tag, ",")
	if len(options) > 0 {
		if options[0] != "" {
			fieldName = options[0]
		}
	}
	structField := &StructField{
		FieldName:  field.Name,
		RenderName: fieldName,
	}
	if len(options) > 1 {
		for _, opt := range options[1:] {
			switch {
			case opt == "omitempty":
				structField.IsOmitEmpty = true
			case opt == "inline":
				structField.IsInline = true
			default:
			}
		}
	}
	return structField
}

func isIgnoredStructField(field reflect.StructField) bool {
	if field.PkgPath != "" && !field.Anonymous {
		// private field
		return true
	}
	tag := getTag(field)
	return tag == "-"
}

type StructFieldMap map[string]*StructField

func structFieldMap(structType reflect.Type) (StructFieldMap, error) {
	structFieldMap := StructFieldMap{}
	renderNameMap := map[string]struct{}{}
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if isIgnoredStructField(field) {
			continue
		}
		structField := structField(field)
		if _, exists := renderNameMap[structField.RenderName]; exists {
			return nil, fmt.Errorf("duplicated struct field name %s", structField.RenderName)
		}
		structFieldMap[structField.FieldName] = structField
		renderNameMap[structField.RenderName] = struct{}{}
	}
	return structFieldMap, nil
}

func encodeValue(value reflect.Value) (interface{}, error) {

	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(value.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uint(value.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return value.Float(), nil
	case reflect.String:
		return value.String(), nil
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return value.Bytes(), nil
		}
	case reflect.Ptr:
		return encodeValue(value.Elem())
	}

	return nil, fmt.Errorf("unknown type: %+v", value.Type().Kind())
}
