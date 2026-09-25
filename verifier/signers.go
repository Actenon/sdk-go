package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
)

const (
	LocalProofKeyID  = "local-proof-v1"
	LocalProofSecret = "actenon-local-proof-secret-v1"
)

type SignatureVerifier interface {
	Verify(payload []byte, signature SignatureSpec) bool
}

type HMACSHA256Verifier struct {
	Secret    []byte
	KeyID     string
	Algorithm string
}

func BuildLocalProofVerifier() HMACSHA256Verifier {
	return HMACSHA256Verifier{
		Secret:    []byte(LocalProofSecret),
		KeyID:     LocalProofKeyID,
		Algorithm: "HS256",
	}
}

func (v HMACSHA256Verifier) Verify(payload []byte, signature SignatureSpec) bool {
	if signature.Algorithm != v.Algorithm || signature.KeyID != v.KeyID || signature.Encoding != "base64url" {
		return false
	}
	provided, err := decodeBase64URL(signature.Value)
	if err != nil {
		return false
	}
	expected := hmac.New(sha256.New, v.Secret)
	expected.Write(payload)
	return hmac.Equal(expected.Sum(nil), provided)
}

var base64URLPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// decodeBase64URL decodes canonical, unpadded base64url. The plain
// base64.RawURLEncoding decoder ignores CR and LF anywhere in its input and
// accepts non-zero trailing bits, so several encodings of one signature
// would verify; only the canonical one is accepted here.
func decodeBase64URL(value string) ([]byte, error) {
	if !base64URLPattern.MatchString(value) {
		return nil, errors.New("value must be unpadded base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(value)
}
