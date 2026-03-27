package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

// Multicodec prefixes for key types.
const (
	codecP256Pub     = multicodec.P256Pub     // 0x1200
	codecSecp256k1   = multicodec.Secp256k1Pub // 0xe7
)

// EncodeDIDKey encodes a public key into did:key format.
// Supports P-256 and secp256k1 curves.
func EncodeDIDKey(pub *ecdsa.PublicKey) (string, error) {
	var codec multicodec.Code
	var keyBytes []byte

	switch {
	case pub.Curve == elliptic.P256():
		codec = codecP256Pub
		keyBytes = elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	case pub.Curve == secp256k1.S256():
		codec = codecSecp256k1
		keyBytes = elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	default:
		return "", fmt.Errorf("unsupported curve: %v", pub.Curve.Params().Name)
	}

	// Encode multicodec varint prefix + compressed public key bytes.
	prefix := multicodecVarint(uint64(codec))
	multikey := append(prefix, keyBytes...)

	// Multibase encode with base58btc ('z' prefix).
	encoded, err := multibase.Encode(multibase.Base58BTC, multikey)
	if err != nil {
		return "", fmt.Errorf("multibase encode: %w", err)
	}

	return "did:key:" + encoded, nil
}

// DecodeDIDKey decodes a did:key string into an ECDSA public key.
func DecodeDIDKey(didKey string) (*ecdsa.PublicKey, error) {
	if len(didKey) < 8 || didKey[:8] != "did:key:" {
		return nil, errors.New("invalid did:key format")
	}

	_, data, err := multibase.Decode(didKey[8:])
	if err != nil {
		return nil, fmt.Errorf("multibase decode: %w", err)
	}

	codec, n := binary.Uvarint(data)
	if n <= 0 {
		return nil, errors.New("invalid multicodec varint")
	}

	keyBytes := data[n:]

	switch multicodec.Code(codec) {
	case codecP256Pub:
		return unmarshalP256Compressed(keyBytes)
	case codecSecp256k1:
		return unmarshalSecp256k1Compressed(keyBytes)
	default:
		return nil, fmt.Errorf("unsupported multicodec: 0x%x", codec)
	}
}

// PublicKeyMultibase returns the multibase-encoded public key (without the did:key: prefix).
func PublicKeyMultibase(pub *ecdsa.PublicKey) (string, error) {
	didKey, err := EncodeDIDKey(pub)
	if err != nil {
		return "", err
	}
	// Strip "did:key:" prefix to get just the multibase string.
	return didKey[8:], nil
}

// CurveType returns a human-readable curve name for a did:key.
func CurveType(didKey string) (string, error) {
	if len(didKey) < 8 || didKey[:8] != "did:key:" {
		return "", errors.New("invalid did:key format")
	}

	_, data, err := multibase.Decode(didKey[8:])
	if err != nil {
		return "", fmt.Errorf("multibase decode: %w", err)
	}

	codec, n := binary.Uvarint(data)
	if n <= 0 {
		return "", errors.New("invalid multicodec varint")
	}

	switch multicodec.Code(codec) {
	case codecP256Pub:
		return "EcdsaSecp256r1VerificationKey2019", nil
	case codecSecp256k1:
		return "EcdsaSecp256k1VerificationKey2019", nil
	default:
		return "", fmt.Errorf("unsupported codec: 0x%x", codec)
	}
}

func multicodecVarint(code uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, code)
	return buf[:n]
}

func unmarshalP256Compressed(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), data)
	if x == nil {
		return nil, errors.New("invalid P-256 compressed point")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

func unmarshalSecp256k1Compressed(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 33 {
		return nil, errors.New("invalid secp256k1 compressed key length")
	}

	// Parse using the decred library for correctness.
	pubKey, err := secp256k1.ParsePubKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 pubkey: %w", err)
	}

	// Convert to standard ecdsa.PublicKey on the secp256k1 curve.
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     pubKey.X(),
		Y:     pubKey.Y(),
	}, nil
}

// IsP256Key checks if the given did:key uses the P-256 curve.
func IsP256Key(didKey string) bool {
	ct, err := CurveType(didKey)
	if err != nil {
		return false
	}
	return ct == "EcdsaSecp256r1VerificationKey2019"
}

// IsSecp256k1Key checks if the given did:key uses the secp256k1 curve.
func IsSecp256k1Key(didKey string) bool {
	ct, err := CurveType(didKey)
	if err != nil {
		return false
	}
	return ct == "EcdsaSecp256k1VerificationKey2019"
}

// KeyFromBigInts creates an ECDSA public key from X, Y coordinates on the specified curve.
func KeyFromBigInts(curve elliptic.Curve, x, y *big.Int) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}
