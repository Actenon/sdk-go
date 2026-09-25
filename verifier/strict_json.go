package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits of the reference's JSON ingress (actenon.core.json
// loads_no_duplicate_keys): 1 MiB of input and 128 levels of nesting, with
// the root counted as level 1.
const (
	maxJSONInputBytes = 1_048_576
	maxJSONDepth      = 128
)

type strictJSONOptions struct {
	// rejectNullContainers refuses null for object, array, boolean and
	// struct members. The reference refuses them (dict(None), expect_bool),
	// while encoding/json would silently decode them as empty or false.
	rejectNullContainers bool
	// rejectEmptyOptionalStrings refuses "" for optional string members
	// (those tagged omitempty). encoding/json cannot distinguish "" from an
	// absent member, while the reference treats a present "" as a value that
	// is signed and bound; the published schemas require minLength >= 1.
	rejectEmptyOptionalStrings bool
	// exactContracts refuses "contract" objects with members other than
	// name and version, as the reference does for trust artifacts.
	exactContracts bool
}

// decodeStrictJSON decodes raw into target (a pointer to a struct) after
// applying the reference's ingress rules and closing the gaps between
// encoding/json and the reference's parser that would otherwise let the Go
// verifier act on a different document than the one the reference sees:
//
//   - input larger than 1 MiB, nested deeper than 128 levels, not valid
//     UTF-8, or carrying unpaired UTF-16 surrogate escapes is refused;
//   - duplicate object members are refused;
//   - a member whose name matches a struct field only case-insensitively
//     (encoding/json would bind "Audience", "AUDIENCE" or "scope" spelled
//     with U+017F LATIN SMALL LETTER LONG S to the audience or scope field)
//     is refused;
//   - trailing data after the top-level value is refused.
func decodeStrictJSON(raw []byte, target any, options strictJSONOptions) error {
	if len(raw) > maxJSONInputBytes {
		return fmt.Errorf("JSON input exceeds maximum size %d bytes", maxJSONInputBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON input must be valid UTF-8")
	}
	if err := rejectUnpairedSurrogateEscapes(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readStrictJSONValue(decoder, 1)
	if err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON input must contain a single top-level value")
	}
	if err := checkJSONShape(value, reflect.TypeOf(target).Elem(), options); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}

func readStrictJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON input exceeds maximum nesting depth %d", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object keys must be strings")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate JSON object key %q", key)
			}
			member, err := readStrictJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = member
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			element, err := readStrictJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, element)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return array, nil
	}
	return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
}

// rejectUnpairedSurrogateEscapes refuses \uD800-\uDFFF escapes that do not
// form a valid surrogate pair. encoding/json replaces them with U+FFFD, so
// they would otherwise alias a literal U+FFFD in the signed document.
func rejectUnpairedSurrogateEscapes(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch character := raw[index]; {
		case character == '"':
			inString = !inString
		case character == '\\' && inString:
			if index+1 < len(raw) && raw[index+1] == 'u' {
				high, ok := parseEscapedCodeUnit(raw, index)
				if !ok {
					return errors.New("invalid JSON unicode escape")
				}
				switch {
				case high >= 0xD800 && high <= 0xDBFF:
					low, ok := parseEscapedCodeUnit(raw, index+6)
					if !ok || low < 0xDC00 || low > 0xDFFF {
						return errors.New("JSON strings must not contain unpaired UTF-16 surrogates")
					}
					index += 11
					continue
				case high >= 0xDC00 && high <= 0xDFFF:
					return errors.New("JSON strings must not contain unpaired UTF-16 surrogates")
				}
				index += 5
				continue
			}
			index++ // skip the escaped character
		}
	}
	return nil
}

func parseEscapedCodeUnit(raw []byte, index int) (uint64, bool) {
	if index+6 > len(raw) || raw[index] != '\\' || raw[index+1] != 'u' {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw[index+2:index+6]), 16, 16)
	return value, err == nil
}

// checkJSONShape walks the generic value alongside the Go type it is about
// to be decoded into.
func checkJSONShape(value any, target reflect.Type, options strictJSONOptions) error {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil // encoding/json reports the type mismatch
		}
		fields := jsonFields(target)
		for key, member := range object {
			field, exact := fields[key]
			if !exact {
				for name := range fields {
					if strings.EqualFold(name, key) {
						return fmt.Errorf("JSON member %q only matches field %q case-insensitively", key, name)
					}
				}
				continue // unknown members are ignored, as by the reference
			}
			if member == nil {
				if options.rejectNullContainers && !nullableKind(field.typ.Kind()) {
					return fmt.Errorf("JSON member %q must not be null", key)
				}
				continue
			}
			if options.rejectEmptyOptionalStrings && field.omitEmpty && field.typ.Kind() == reflect.String && member == "" {
				return fmt.Errorf("JSON member %q must not be an empty string", key)
			}
			if options.exactContracts && key == "contract" {
				if contract, ok := member.(map[string]any); ok && len(contract) != 2 {
					return errors.New("contract must contain exactly name and version")
				}
			}
			if err := checkJSONShape(member, field.typ, options); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return nil
		}
		element := target.Elem()
		for _, item := range array {
			if item == nil {
				if options.rejectNullContainers && element.Kind() != reflect.Interface && element.Kind() != reflect.Pointer {
					return errors.New("JSON array elements must not be null")
				}
				continue
			}
			if err := checkJSONShape(item, element, options); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for _, member := range object {
			if member == nil {
				continue
			}
			if err := checkJSONShape(member, target.Elem(), options); err != nil {
				return err
			}
		}
	}
	return nil
}

// nullableKind reports whether the reference treats null like an absent
// member for a field of this kind: optional strings (None) and pointers.
func nullableKind(kind reflect.Kind) bool {
	return kind == reflect.String || kind == reflect.Pointer || kind == reflect.Interface
}

type jsonField struct {
	typ       reflect.Type
	omitEmpty bool
}

func jsonFields(target reflect.Type) map[string]jsonField {
	fields := map[string]jsonField{}
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		if !field.IsExported() {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, flags, _ := strings.Cut(tag, ",")
		if name == "" {
			name = field.Name
		}
		fields[name] = jsonField{typ: field.Type, omitEmpty: strings.Contains(","+flags+",", ",omitempty,")}
	}
	return fields
}
