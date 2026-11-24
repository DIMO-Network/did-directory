package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/multiformats/go-multicodec"
)

// curveSecp256k1 is the KeyEntry curve of a secp256k1 key, whose
// PrivateKeyBase64 is the raw 32-byte scalar (PKCS#8 has no secp256k1).
const curveSecp256k1 = "secp256k1"

// localRootFor picks the kind of key a new DID's local root is. An org's is
// secp256k1, the type of a Turnkey org root, which the SDK's org policy
// requires to extend the org. A person's and a car's stay P-256.
func localRootFor(opts createOptions) (*fileSigner, error) {
	if opts.Controller == "" && (opts.Org || opts.OrgKey != "" || opts.OrgHost != "") {
		return newFileSignerK1()
	}
	return newFileSignerNew()
}

// newFileSignerK1 generates a fresh secp256k1 key.
func newFileSignerK1() (*fileSigner, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return &fileSigner{k1: k, didKey: dimocrypto.FromSecp256k1(k.PubKey()).DIDKey()}, nil
}

// signSecp256k1 is SignOperation for a secp256k1 key: base64url r||s over the
// SHA-256 of data, each half 32 bytes.
func signSecp256k1(k *secp256k1.PrivateKey, data []byte) string {
	h := sha256.Sum256(data)
	sig := dcrecdsa.Sign(k, h[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	return base64.RawURLEncoding.EncodeToString(append(rb[:], sb[:]...))
}

// saveSigner stores a keystore signer's key as the DID's key.
func saveSigner(did string, s *fileSigner) error {
	if s.k1 != nil {
		return writeK1Key(keyFilePath(did), did, s.k1)
	}
	return SaveKey(did, s.key)
}

// loadSigner returns the keystore signer for a DID's key, P-256 or secp256k1.
func loadSigner(did string) (*fileSigner, error) {
	return readSigner(keyFilePath(did))
}

// pubkeyOf is the did:key of a DID's keystore key, or of its #dimo_org key.
func pubkeyOf(did string, org bool) (string, error) {
	if org {
		k, err := LoadOrgKey(did)
		if err != nil {
			return "", err
		}
		return dimocrypto.EncodeDIDKey(&k.PublicKey)
	}
	s, err := loadSigner(did)
	if err != nil {
		return "", err
	}
	return s.DIDKey(), nil
}

// newCustodyLike is newCustody for a key replacing current: a keystore key of
// the same curve, so a rotated org root stays secp256k1.
func newCustodyLike(ctx context.Context, tk *turnkeyFlags, current string) (string, func(string) error, error) {
	if !tk.enabled() {
		if pub, err := didkey.Decode(current); err == nil && pub.Codec() == multicodec.Secp256k1Pub {
			s, err := newFileSignerK1()
			if err != nil {
				return "", nil, err
			}
			return s.DIDKey(), func(d string) error { return saveSigner(d, s) }, nil
		}
	}
	return newCustody(ctx, tk)
}
