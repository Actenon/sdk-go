package verifier

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
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

// Ed25519Verifier verifies EdDSA (Ed25519) PCCB signatures, the algorithm
// the Kernel and Permit use for production proofs, against pinned public
// keys selected by signature.key_id. It verifies the same signing input as
// the reference: the canonical unsigned PCCB payload.
type Ed25519Verifier struct {
	keys map[string]ed25519.PublicKey
}

// NewEd25519Verifier pins the given public keys by key ID. Historical keys
// that must still verify older proofs are pinned alongside the active one.
func NewEd25519Verifier(keys map[string]ed25519.PublicKey) (*Ed25519Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one Ed25519 public key is required")
	}
	pinned := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, key := range keys {
		if keyID == "" {
			return nil, errors.New("Ed25519 key IDs must be non-empty")
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 public key %q must be %d bytes", keyID, ed25519.PublicKeySize)
		}
		pinned[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return &Ed25519Verifier{keys: pinned}, nil
}

// NewEd25519VerifierFromJWKs pins public keys published as OKP/Ed25519 JWKs
// (for example an issuer's public_key.jwk.json), keyed by their "kid".
func NewEd25519VerifierFromJWKs(jwks ...[]byte) (*Ed25519Verifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(jwks))
	for _, raw := range jwks {
		keyID, key, err := ParseEd25519PublicJWK(raw)
		if err != nil {
			return nil, err
		}
		if _, duplicate := keys[keyID]; duplicate {
			return nil, fmt.Errorf("duplicate Ed25519 key ID %q", keyID)
		}
		keys[keyID] = key
	}
	return NewEd25519Verifier(keys)
}

// ParseEd25519PublicJWK returns the key ID and public key of an OKP/Ed25519
// JWK. JWKs carrying private key material ("d") are refused.
func ParseEd25519PublicJWK(raw []byte) (string, ed25519.PublicKey, error) {
	var jwk map[string]any
	if err := decodeStrictJSON(raw, &jwk, strictJSONOptions{}); err != nil {
		return "", nil, errors.New("Ed25519 JWK must be a JSON object")
	}
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		return "", nil, errors.New("Ed25519 JWK must declare kty OKP and crv Ed25519")
	}
	if algorithm, present := jwk["alg"]; present && algorithm != "EdDSA" {
		return "", nil, errors.New("Ed25519 JWK alg must be EdDSA")
	}
	if _, present := jwk["d"]; present {
		return "", nil, errors.New("Ed25519 JWK must not contain private key material")
	}
	keyID, ok := jwk["kid"].(string)
	if !ok || keyID == "" {
		return "", nil, errors.New("Ed25519 JWK must have a non-empty kid")
	}
	x, ok := jwk["x"].(string)
	if !ok {
		return "", nil, errors.New("Ed25519 JWK must have an x member")
	}
	key, err := decodeBase64URL(x)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return "", nil, errors.New("Ed25519 JWK x must encode a 32-byte public key")
	}
	return keyID, ed25519.PublicKey(key), nil
}

// Verify reports whether signature is a valid EdDSA signature over payload
// by the key pinned under signature.KeyID.
func (v *Ed25519Verifier) Verify(payload []byte, signature SignatureSpec) bool {
	if v == nil || signature.Algorithm != "EdDSA" || signature.Encoding != "base64url" {
		return false
	}
	key, ok := v.keys[signature.KeyID]
	if !ok {
		return false
	}
	raw, err := decodeBase64URL(signature.Value)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(key, payload, raw)
}
