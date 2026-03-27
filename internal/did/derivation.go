package did

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/multiformats/go-multihash"
)

const (
	// DIDPrefix is the method prefix for DIMO DIDs.
	DIDPrefix = "did:dimo:"

	// truncLen is the length to truncate the base32 hash for the DID identifier.
	truncLen = 24
)

// dagCBOREncMode uses canonical CBOR settings that match DAG-CBOR requirements:
// deterministic map key ordering, no indefinite-length items.
var dagCBOREncMode cbor.EncMode

func init() {
	opts := cbor.CanonicalEncOptions()
	// DAG-CBOR requires length-first map key ordering (canonical CBOR).
	var err error
	dagCBOREncMode, err = opts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("failed to create DAG-CBOR enc mode: %v", err))
	}
}

// DeriveFromGenesis computes a did:dimo identifier from a genesis operation.
// DID = "did:dimo:" + lowercase(base32(sha256(dag-cbor(genesis_op_unsigned))))[:24]
func DeriveFromGenesis(op *Operation) (string, error) {
	unsigned := op.ToUnsigned()

	cborBytes, err := MarshalDAGCBOR(unsigned)
	if err != nil {
		return "", fmt.Errorf("dag-cbor encode: %w", err)
	}

	hash := sha256.Sum256(cborBytes)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	encoded = strings.ToLower(encoded)

	if len(encoded) > truncLen {
		encoded = encoded[:truncLen]
	}

	return DIDPrefix + encoded, nil
}

// ComputeCID computes the CID (Content Identifier) of an operation.
// Uses SHA-256 hash of DAG-CBOR encoding, returned as a base58-encoded multihash string.
func ComputeCID(op *Operation) (string, error) {
	unsigned := op.ToUnsigned()

	cborBytes, err := MarshalDAGCBOR(unsigned)
	if err != nil {
		return "", fmt.Errorf("dag-cbor encode: %w", err)
	}

	mh, err := multihash.Sum(cborBytes, multihash.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("multihash: %w", err)
	}

	return mh.B58String(), nil
}

// MarshalDAGCBOR encodes a value as deterministic CBOR bytes (DAG-CBOR compatible).
// Uses canonical CBOR encoding with sorted map keys.
func MarshalDAGCBOR(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := dagCBOREncMode.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("cbor encode: %w", err)
	}
	return buf.Bytes(), nil
}

// ParseDID extracts the identifier portion of a did:dimo: string.
func ParseDID(did string) (string, error) {
	if !strings.HasPrefix(did, DIDPrefix) {
		return "", fmt.Errorf("invalid DID: must start with %s", DIDPrefix)
	}
	id := did[len(DIDPrefix):]
	if len(id) == 0 {
		return "", fmt.Errorf("invalid DID: empty identifier")
	}
	return id, nil
}

// IsValidDID checks if a string is a syntactically valid did:dimo identifier.
func IsValidDID(did string) bool {
	_, err := ParseDID(did)
	return err == nil
}
