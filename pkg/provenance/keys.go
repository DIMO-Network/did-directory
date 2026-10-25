package provenance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
)

// ErrUnknownKey is a kid that names no verification method.
var ErrUnknownKey = errors.New("unknown key")

// Resolver fetches a DID document; *client.Client is one.
type Resolver interface {
	Resolve(ctx context.Context, did string) (*did.DIDDocument, error)
}

// DIDKeys finds keys for did:key identifiers locally, which is what a machine
// with no directory entry signs with, and for any other DID through a
// directory resolver. Directory may be nil, in which case only did:key works.
//
// A directory DID is resolved as it is now. A signature by a key the source
// has since rotated away no longer verifies through DIDKeys; checking old
// signatures needs the key that was published at the time.
type DIDKeys struct {
	Directory Resolver
}

// Key implements Keys.
func (k DIDKeys) Key(ctx context.Context, kid string) (*didkey.PublicKey, error) {
	id, frag, ok := strings.Cut(kid, "#")
	if !ok || frag == "" {
		return nil, fmt.Errorf("%w: kid %q has no fragment", ErrUnknownKey, kid)
	}
	if strings.HasPrefix(id, "did:key:") {
		// A did:key has exactly one key, and its fragment is the key itself.
		if frag != strings.TrimPrefix(id, "did:key:") {
			return nil, fmt.Errorf("%w: %s", ErrUnknownKey, kid)
		}
		return didkey.Decode(id)
	}
	if k.Directory == nil {
		return nil, fmt.Errorf("%w: no directory to resolve %s", ErrUnknownKey, id)
	}
	doc, err := k.Directory.Resolve(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, vm := range doc.VerificationMethod {
		if vm.ID == kid {
			return didkey.DecodeMultibase(vm.PublicKeyMultibase)
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownKey, kid)
}
