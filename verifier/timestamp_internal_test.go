package verifier

import (
	"errors"
	"testing"
	"time"
)

// Timestamps follow RFC 3339 section 5.6 date-time as the Actenon reference
// parses it (actenon-kernel evidence/release/north-star/differential,
// corpus-addendum-timestamp-grammar). Go's time.Parse additionally accepts a
// "," decimal sign; the SDK must not.
func TestParseTimestampGrammar(t *testing.T) {
	want := time.Date(2026, 1, 1, 12, 0, 0, 500000000, time.UTC)
	for _, raw := range []string{
		"2026-01-01T12:00:00.5Z",
		"2026-01-01T12:00:00.500Z",
		"2026-01-01T12:00:00.5000009Z", // truncated to microseconds
		"2026-01-01T17:30:00.5+05:30",
	} {
		got, err := parseTimestamp(raw, "issued_at", ErrInvalidIntent)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseTimestamp(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"2026-01-01T12:00:00,5Z", // the case Go accepts and RFC 3339 does not
		"2026-01-01T12:00:00,500000+00:00",
		"2026-01-01T12:00Z",
		"20260101T120000Z",
		"2026-01-01T12:00:00+0000",
	} {
		_, err := parseTimestamp(raw, "issued_at", ErrInvalidIntent)
		var verr *VerificationError
		if !errors.As(err, &verr) || verr.Code != ErrInvalidTimestamp {
			t.Errorf("parseTimestamp(%q) error = %v; want %s", raw, err, ErrInvalidTimestamp)
		}
	}
	if _, err := parseRFC3339("2026-01-01T12:00:00,5Z"); !errors.Is(err, errCommaFraction) {
		t.Errorf("parseRFC3339 comma fraction error = %v; want errCommaFraction", err)
	}
}
