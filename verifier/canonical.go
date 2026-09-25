package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// CanonicalizationProfile is the canonicalisation identifier the Kernel
	// stamps on newly minted proofs, receipt digests and approvals.
	CanonicalizationProfile = "ACTENON-JCS-STRICT-1"
	// LegacyCanonicalizationProfile is the identifier carried by historical
	// artifacts. It names the same canonicalisation rules and remains
	// accepted.
	LegacyCanonicalizationProfile = "RFC8785-JCS"
)

// IsAcceptedCanonicalization reports whether label is a canonicalisation
// profile accepted by the reference verifier.
func IsAcceptedCanonicalization(label string) bool {
	return label == CanonicalizationProfile || label == LegacyCanonicalizationProfile
}

// maxCanonicalDepth and maxCanonicalOutputBytes are the ACTENON-JCS-STRICT-1
// limits enforced by the reference canonicaliser: no value may sit deeper
// than 128 levels (the root is level 1) and the output may not exceed 1 MiB.
const (
	maxCanonicalDepth       = 128
	maxCanonicalOutputBytes = 1_048_576
)

var canonicalIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func canonicalizeJSON(value any) (string, error) {
	var builder strings.Builder
	if err := writeCanonicalJSON(&builder, value, 1); err != nil {
		return "", err
	}
	if builder.Len() > maxCanonicalOutputBytes {
		return "", fmt.Errorf("canonical JSON output exceeds maximum size %d bytes", maxCanonicalOutputBytes)
	}
	return builder.String(), nil
}

func canonicalizeBytes(value any) ([]byte, error) {
	canonical, err := canonicalizeJSON(value)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func sha256Hex(value any) (string, error) {
	canonical, err := canonicalizeBytes(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// writeCanonicalString encodes a string exactly like the reference
// canonicaliser (Python json.dumps with ensure_ascii=False): only '"', '\\'
// and C0 control characters are escaped; everything else, including '<',
// '>', '&', U+2028 and U+2029, is emitted as raw UTF-8. Invalid UTF-8 has no
// canonical form and is refused rather than replaced.
func writeCanonicalString(builder *strings.Builder, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("canonical JSON strings must be valid UTF-8")
	}
	builder.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\f':
			builder.WriteString(`\f`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(builder, `\u%04x`, r)
			} else {
				builder.WriteRune(r)
			}
		}
	}
	builder.WriteByte('"')
	return nil
}

func writeCanonicalJSON(builder *strings.Builder, value any, depth int) error {
	if depth > maxCanonicalDepth {
		return fmt.Errorf("JSON value exceeds maximum nesting depth %d", maxCanonicalDepth)
	}
	if value == nil {
		builder.WriteString("null")
		return nil
	}

	switch typed := value.(type) {
	case bool:
		if typed {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
		return nil
	case string:
		return writeCanonicalString(builder, typed)
	case json.Number:
		raw := typed.String()
		if !canonicalIntegerPattern.MatchString(raw) {
			return fmt.Errorf("floating-point values are not supported in canonical action hashing")
		}
		// JSON "-0" is the integer zero, which the reference renders as "0".
		if raw == "-0" {
			raw = "0"
		}
		builder.WriteString(raw)
		return nil
	case int:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int8:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int16:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int32:
		builder.WriteString(strconv.FormatInt(int64(typed), 10))
		return nil
	case int64:
		builder.WriteString(strconv.FormatInt(typed, 10))
		return nil
	case uint:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint8:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint16:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint32:
		builder.WriteString(strconv.FormatUint(uint64(typed), 10))
		return nil
	case uint64:
		builder.WriteString(strconv.FormatUint(typed, 10))
		return nil
	case float32, float64:
		return fmt.Errorf("floating-point values are not supported in canonical action hashing")
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		builder.WriteByte('[')
		for index := 0; index < reflected.Len(); index++ {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := writeCanonicalJSON(builder, reflected.Index(index).Interface(), depth+1); err != nil {
				return err
			}
		}
		builder.WriteByte(']')
		return nil
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("canonical JSON object keys must be strings")
		}
		keys := reflected.MapKeys()
		sortedKeys := make([]string, 0, len(keys))
		for _, key := range keys {
			sortedKeys = append(sortedKeys, key.String())
		}
		sort.Strings(sortedKeys)
		builder.WriteByte('{')
		for index, key := range sortedKeys {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := writeCanonicalString(builder, key); err != nil {
				return err
			}
			builder.WriteByte(':')
			if err := writeCanonicalJSON(builder, reflected.MapIndex(reflect.ValueOf(key)).Interface(), depth+1); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("unsupported value type for canonicalization: %T", value)
	}
}
