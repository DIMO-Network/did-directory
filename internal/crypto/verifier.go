package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// VerifySignature verifies an ECDSA-SHA256 signature against the provided data and public key.
// The sig should be base64url-encoded r||s format.
func VerifySignature(pub *ecdsa.PublicKey, data []byte, sig string) error {
	byteSize := (pub.Curve.Params().BitSize + 7) / 8

	r, s, err := DecodeSignature(sig, byteSize)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256(data)

	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("invalid signature")
	}

	return nil
}

// VerifyWithDIDKey verifies a signature using a did:key encoded public key.
func VerifyWithDIDKey(didKey string, data []byte, sig string) error {
	pub, err := DecodeDIDKey(didKey)
	if err != nil {
		return fmt.Errorf("decode did:key: %w", err)
	}

	return VerifySignature(pub, data, sig)
}
