package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// SignOperation signs the given data bytes with the private key using ECDSA-SHA256.
// Returns a base64url-encoded signature (r || s, each 32 bytes zero-padded).
func SignOperation(key *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}

	// Determine byte size from the curve order.
	byteSize := (key.Curve.Params().BitSize + 7) / 8

	// Encode as fixed-size r || s.
	sig := make([]byte, 2*byteSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(sig[byteSize-len(rBytes):byteSize], rBytes)
	copy(sig[2*byteSize-len(sBytes):], sBytes)

	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// DecodeSignature decodes a base64url-encoded r||s signature into big.Int components.
func DecodeSignature(sig string, byteSize int) (*big.Int, *big.Int, error) {
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("base64url decode: %w", err)
	}

	if len(sigBytes) != 2*byteSize {
		return nil, nil, fmt.Errorf("invalid signature length: got %d, want %d", len(sigBytes), 2*byteSize)
	}

	r := new(big.Int).SetBytes(sigBytes[:byteSize])
	s := new(big.Int).SetBytes(sigBytes[byteSize:])

	return r, s, nil
}
