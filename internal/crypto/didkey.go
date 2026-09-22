package crypto

import (
	"crypto/ecdsa"

	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PublicKey is a verification key on one of the curves did:key supports. The
// implementation lives in pkg/didkey so that services outside this module can
// check signatures against a DID document; these are the names the directory's
// own code uses.
type PublicKey = didkey.PublicKey

// FromECDSA wraps a standard library P-256 key.
func FromECDSA(pub *ecdsa.PublicKey) (*PublicKey, error) { return didkey.FromECDSA(pub) }

// FromSecp256k1 wraps a decred secp256k1 key.
func FromSecp256k1(pub *secp256k1.PublicKey) *PublicKey { return didkey.FromSecp256k1(pub) }

// EncodeDIDKey encodes a standard library P-256 public key as did:key.
func EncodeDIDKey(pub *ecdsa.PublicKey) (string, error) { return didkey.Encode(pub) }

// DecodeDIDKey decodes a did:key string. P-256 and secp256k1 are supported.
func DecodeDIDKey(s string) (*PublicKey, error) { return didkey.Decode(s) }
