// Package identity is the profile of the identity tokens dauth issues after a
// DID signs in, shared by dauth, which issues them, and the services that take
// them. A token says what it may be used for (scope) and which key must
// present it (cnf.jkt, RFC 9449): the DID's signature at sign-in covers both,
// so a token is neither a blank cheque nor usable by whoever copies it.
package identity

import (
	"fmt"
	"slices"
	"strings"
)

// The scopes an identity token may carry. They are independent: a token
// holds exactly the ones the DID asked for when it signed in.
const (
	// ScopeRead reads: records, logs, the access and proof views, /me, and
	// /authorize (an issuer's question), and is what /exchange requires.
	ScopeRead = "read"
	// ScopeWrite writes records and withdraws pending writes.
	ScopeWrite = "write"
	// ScopeApprove approves pending writes, revokes by author and registers a
	// repository: the acts the host puts behind a second look. dauth issues
	// it for a short time only.
	ScopeApprove = "approve"
)

// Scopes lists every scope, in the order a scope claim is written.
var Scopes = []string{ScopeRead, ScopeWrite, ScopeApprove}

// ParseScope reads a scope claim: known scopes separated by spaces, at least
// one, none twice. It returns them in Scopes order.
func ParseScope(claim string) ([]string, error) {
	fields := strings.Fields(claim)
	if len(fields) == 0 {
		return nil, fmt.Errorf("scope is required (one or more of %s)", strings.Join(Scopes, ", "))
	}
	for i, f := range fields {
		if !slices.Contains(Scopes, f) {
			return nil, fmt.Errorf("unknown scope %q", f)
		}
		if slices.Contains(fields[:i], f) {
			return nil, fmt.Errorf("scope %q appears twice", f)
		}
	}
	out := make([]string, 0, len(fields))
	for _, s := range Scopes {
		if slices.Contains(fields, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// FormatScope writes scopes as a scope claim.
func FormatScope(scopes []string) string { return strings.Join(scopes, " ") }

// Confirmation is the cnf claim: the RFC 7638 thumbprint of the key whose
// DPoP proofs must accompany the token.
type Confirmation struct {
	JKT string `json:"jkt"`
}
