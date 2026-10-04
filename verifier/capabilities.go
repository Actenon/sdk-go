package verifier

import "strings"

// GlobChars are grant-scope metacharacters. A proof names concrete
// capabilities only; a verifier must not expand these.
const GlobChars = "*?[]"

// CapabilityError is a capability set that would widen, or an authority
// extension that cannot be used.
type CapabilityError struct {
	Message string
}

func (e *CapabilityError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func capabilityError(message string) error {
	return &CapabilityError{Message: message}
}

// IsConcreteCapability reports whether value is one non-empty capability
// string that contains no glob character.
func IsConcreteCapability(value string) bool {
	return value != "" && !strings.ContainsAny(value, GlobChars)
}

func requireConcrete(capabilities []string, emptyMessage string) ([]string, error) {
	if len(capabilities) == 0 {
		return nil, capabilityError(emptyMessage)
	}
	concrete := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		if !IsConcreteCapability(capability) {
			return nil, capabilityError("proof capability must name one concrete action; a wildcard is not a capability")
		}
		concrete = append(concrete, capability)
	}
	return concrete, nil
}

// ScopeCapabilitiesForMint is the exact capability set a proof may carry.
// An empty slice is refused. It is not replaced by the attempted action or
// by "*".
func ScopeCapabilitiesForMint(capabilities []string) ([]string, error) {
	return requireConcrete(capabilities, "empty allow-list cannot mint a proof; refusing to widen to the attempted action")
}

// ScopeCapabilitiesForVerification is the set an edge compares the intent
// capability against.
//
// A nil slice means the caller passed no allow-list. The set is then exactly
// that one capability, and it is not a second allow-list. An empty non-nil
// slice stays empty: it authorises nothing, and it is not replaced by the
// attempted action or by "*".
//
// Verify does not apply the nil substitution. VerificationContext.ScopeCapabilities
// is the edge declaration, and both nil and empty refuse with
// SCOPE_CAPABILITY_MISMATCH.
func ScopeCapabilitiesForVerification(declared []string, intentCapability string) ([]string, error) {
	if !IsConcreteCapability(intentCapability) {
		return nil, capabilityError("intent capability must name one concrete action; a wildcard is not a capability")
	}
	if declared == nil {
		return []string{intentCapability}, nil
	}
	if len(declared) == 0 {
		return []string{}, nil
	}
	return requireConcrete(declared, "empty edge allow-list authorises nothing")
}

// CapabilityInScope reports exact membership. A glob does not match,
// including a glob equal to itself, and a glob anywhere in declared
// fails the set.
func CapabilityInScope(capability string, declared []string) bool {
	if !IsConcreteCapability(capability) {
		return false
	}
	found := false
	for _, item := range declared {
		if !IsConcreteCapability(item) {
			return false
		}
		if item == capability {
			found = true
		}
	}
	return found
}

// AuthorityExtension is the signed grant reference at extensions.authority.
type AuthorityExtension struct {
	Issuer    string `json:"issuer"`
	GrantID   string `json:"grant_id"`
	Revocable bool   `json:"revocable"`
}

// AuthorityExtensionObject is the extensions object an issuer embeds when
// the grant is revocable. revocable is explicit; there is no implicit true.
func AuthorityExtensionObject(issuer, grantID string, revocable bool) (map[string]any, error) {
	if issuer == "" {
		return nil, capabilityError("authority extension requires an issuer")
	}
	if grantID == "" {
		return nil, capabilityError("authority extension requires a grant_id")
	}
	return map[string]any{
		"authority": map[string]any{
			"issuer":    issuer,
			"grant_id":  grantID,
			"revocable": revocable,
		},
	}, nil
}

// ParseAuthorityExtension returns extensions.authority.
// A missing or unusable object is a CapabilityError.
func ParseAuthorityExtension(extensions map[string]any) (AuthorityExtension, error) {
	if extensions == nil {
		return AuthorityExtension{}, capabilityError("proof carries no authority extension")
	}
	raw, ok := extensions["authority"]
	if !ok {
		return AuthorityExtension{}, capabilityError("proof carries no authority extension")
	}
	authority, ok := raw.(map[string]any)
	if !ok {
		return AuthorityExtension{}, capabilityError("proof carries no authority extension")
	}
	issuer, ok := authority["issuer"].(string)
	if !ok || issuer == "" {
		return AuthorityExtension{}, capabilityError("authority extension requires an issuer")
	}
	grantID, ok := authority["grant_id"].(string)
	if !ok || grantID == "" {
		return AuthorityExtension{}, capabilityError("authority extension requires a grant_id")
	}
	revocable, ok := authority["revocable"].(bool)
	if !ok {
		return AuthorityExtension{}, capabilityError("authority extension revocable must be a boolean")
	}
	return AuthorityExtension{Issuer: issuer, GrantID: grantID, Revocable: revocable}, nil
}

// Authority returns the proof's signed grant reference.
func (p PCCB) Authority() (AuthorityExtension, error) {
	return ParseAuthorityExtension(p.Extensions)
}

// UnauthenticatedRefusal is the refusal code when a token has not been
// cryptographically accepted. The boolean is false only when a trust root
// is configured and the signature verified. Token length, a "v1." prefix,
// and well-formed JSON are not arguments: parsing is not acceptance.
func UnauthenticatedRefusal(trustRootConfigured, signatureVerified bool) (VerificationErrorCode, bool) {
	if !trustRootConfigured {
		return ErrIssuerUntrusted, true
	}
	if !signatureVerified {
		return ErrSignatureInvalid, true
	}
	return "", false
}
