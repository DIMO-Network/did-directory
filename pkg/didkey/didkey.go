// Package didkey encodes and decodes did:key identifiers and the multikey
// publicKeyMultibase values a DID document carries, and verifies signatures
// made by them. P-256 and secp256k1 are supported. It is the one place the
// directory, the org host, dauth and any offline verifier agree on what a key
// in a DID document is.
package didkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

// Multicodec prefixes for key types.
const (
	codecP256Pub   = multicodec.P256Pub      // 0x1200
	codecSecp256k1 = multicodec.Secp256k1Pub // 0xe7
)

// Size in bytes of a coordinate, and of each half of a signature, on both
// supported curves.
const coordSize = 32

// PublicKey is a verification key on one of the curves did:key supports.
// P-256 keys are held as the standard library's ecdsa.PublicKey; secp256k1
// keys are held in the decred library's native form, since the standard
// library only implements the NIST curves. Exactly one of the two is set.
type PublicKey struct {
	codec multicodec.Code
	p256  *ecdsa.PublicKey
	k1    *secp256k1.PublicKey
}

// FromECDSA wraps a standard library P-256 key. Other curves are rejected.
func FromECDSA(pub *ecdsa.PublicKey) (*PublicKey, error) {
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported curve: %v", pub.Curve.Params().Name)
	}
	return &PublicKey{codec: codecP256Pub, p256: pub}, nil
}

// FromSecp256k1 wraps a decred secp256k1 key.
func FromSecp256k1(pub *secp256k1.PublicKey) *PublicKey {
	return &PublicKey{codec: codecSecp256k1, k1: pub}
}

// Codec returns the multicodec that identifies the key's curve in did:key.
func (k *PublicKey) Codec() multicodec.Code { return k.codec }

// Compressed returns the 33-byte SEC 1 compressed encoding of the point.
func (k *PublicKey) Compressed() []byte {
	switch k.codec {
	case codecP256Pub:
		// Bytes never fails for a P-256 key that came through FromECDSA.
		uncompressed, err := k.p256.Bytes()
		if err != nil {
			panic("didkey: P-256 key is not encodable: " + err.Error())
		}
		out := make([]byte, 1+coordSize)
		out[0] = 0x02 | uncompressed[2*coordSize]&1
		copy(out[1:], uncompressed[1:1+coordSize])
		return out
	case codecSecp256k1:
		return k.k1.SerializeCompressed()
	default:
		panic(fmt.Sprintf("didkey: public key has unknown codec 0x%x", uint64(k.codec)))
	}
}

// Multibase returns the base58btc multibase encoding of the multicodec prefix
// and compressed point, which is the did:key identifier without its prefix.
func (k *PublicKey) Multibase() string {
	multikey := append(multicodecVarint(uint64(k.codec)), k.Compressed()...)
	// Encode only fails for an unknown base, and this one is fixed.
	encoded, err := multibase.Encode(multibase.Base58BTC, multikey)
	if err != nil {
		panic("didkey: multibase encode: " + err.Error())
	}
	return encoded
}

// DIDKey returns the key as a did:key identifier.
func (k *PublicKey) DIDKey() string {
	return "did:key:" + k.Multibase()
}

// Verify checks a base64url r || s signature over the SHA-256 hash of data,
// the form SignOperation and repo commits use.
func (k *PublicKey) Verify(data []byte, sig string) error {
	raw, err := decodeSignature(sig, coordSize)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256(data)

	switch k.codec {
	case codecP256Pub:
		r := new(big.Int).SetBytes(raw[:coordSize])
		s := new(big.Int).SetBytes(raw[coordSize:])
		if !ecdsa.Verify(k.p256, hash[:], r, s) {
			return errors.New("invalid signature")
		}
		return nil
	case codecSecp256k1:
		var r, s secp256k1.ModNScalar
		if r.SetByteSlice(raw[:coordSize]) || s.SetByteSlice(raw[coordSize:]) {
			// A component at or above the group order is never a valid
			// signature; SetByteSlice reports that as overflow.
			return errors.New("invalid signature")
		}
		if !dcrecdsa.NewSignature(&r, &s).Verify(hash[:], k.k1) {
			return errors.New("invalid signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported codec: 0x%x", uint64(k.codec))
	}
}

// Encode encodes a standard library P-256 public key as did:key.
func Encode(pub *ecdsa.PublicKey) (string, error) {
	k, err := FromECDSA(pub)
	if err != nil {
		return "", err
	}
	return k.DIDKey(), nil
}

// Decode decodes a did:key string. P-256 and secp256k1 are supported.
func Decode(didKey string) (*PublicKey, error) {
	if len(didKey) < 8 || didKey[:8] != "did:key:" {
		return nil, errors.New("invalid did:key format")
	}
	return DecodeMultibase(didKey[8:])
}

// DecodeMultibase decodes a multikey as a DID document's publicKeyMultibase
// carries it: the did:key identifier without its prefix.
func DecodeMultibase(encoded string) (*PublicKey, error) {
	_, data, err := multibase.Decode(encoded)
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

func multicodecVarint(code uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, code)
	return buf[:n]
}

func unmarshalP256Compressed(data []byte) (*PublicKey, error) {
	// The standard library only parses uncompressed points, so decompress
	// with crypto/elliptic first and hand it the SEC 1 uncompressed form.
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), data)
	if x == nil {
		return nil, errors.New("invalid P-256 compressed point")
	}
	uncompressed := make([]byte, 1+2*coordSize)
	uncompressed[0] = 0x04
	x.FillBytes(uncompressed[1 : 1+coordSize])
	y.FillBytes(uncompressed[1+coordSize:])
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("parse P-256 point: %w", err)
	}
	return &PublicKey{codec: codecP256Pub, p256: pub}, nil
}

func unmarshalSecp256k1Compressed(data []byte) (*PublicKey, error) {
	if len(data) != 1+coordSize {
		return nil, errors.New("invalid secp256k1 compressed key length")
	}
	pub, err := secp256k1.ParsePubKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 pubkey: %w", err)
	}
	return FromSecp256k1(pub), nil
}

// decodeSignature decodes a base64url-encoded r||s signature, checking that
// it holds exactly two byteSize components.
func decodeSignature(sig string, byteSize int) ([]byte, error) {
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	if len(sigBytes) != 2*byteSize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(sigBytes), 2*byteSize)
	}
	return sigBytes, nil
}
