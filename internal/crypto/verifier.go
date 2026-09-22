package crypto

import (
	"fmt"
)

// VerifySignature verifies a base64url r||s signature over the SHA-256 hash
// of data against pub.
func VerifySignature(pub *PublicKey, data []byte, sig string) error {
	return pub.Verify(data, sig)
}

// VerifyWithDIDKey verifies a signature using a did:key encoded public key.
func VerifyWithDIDKey(didKey string, data []byte, sig string) error {
	pub, err := DecodeDIDKey(didKey)
	if err != nil {
		return fmt.Errorf("decode did:key: %w", err)
	}

	return VerifySignature(pub, data, sig)
}
