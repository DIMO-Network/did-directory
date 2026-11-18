package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Fixed private keys for the golden vectors. They are test material only.
const (
	vectorWalletKeyHex = "1111111111111111111111111111111111111111111111111111111111111111" // secp256k1
	vectorPhoneKeyHex  = "2222222222222222222222222222222222222222222222222222222222222222" // P-256
	vectorCLIKeyHex    = "3333333333333333333333333333333333333333333333333333333333333333" // secp256k1
)

// Vector is one golden DID operation with every encoding of it.
type Vector struct {
	Name                string            `json:"name"`
	Unsigned            UnsignedOperation `json:"unsigned"`
	PayloadHex          string            `json:"payloadHex"`
	CBORHex             string            `json:"cborHex"`
	DID                 string            `json:"did"`
	CID                 string            `json:"cid"`
	SignerDIDKey        string            `json:"signerDidKey"`
	SignerPrivateKeyHex string            `json:"signerPrivateKeyHex"`
	Sig                 string            `json:"sig"`
}

// VectorFile is the content of testdata/vectors/did-ops.json.
type VectorFile struct {
	Version int      `json:"version"`
	Cases   []Vector `json:"cases"`
}

// GenerateVectors builds the golden vectors. Everything is deterministic
// including the signatures: decred's ecdsa.Sign is RFC 6979 deterministic.
func GenerateVectors() (VectorFile, error) {
	walletBytes, err := hex.DecodeString(vectorWalletKeyHex)
	if err != nil {
		return VectorFile{}, fmt.Errorf("wallet key: %w", err)
	}
	wallet := secp256k1.PrivKeyFromBytes(walletBytes)
	cliBytes, err := hex.DecodeString(vectorCLIKeyHex)
	if err != nil {
		return VectorFile{}, fmt.Errorf("cli key: %w", err)
	}
	cli := secp256k1.PrivKeyFromBytes(cliBytes)
	phoneBytes, err := hex.DecodeString(vectorPhoneKeyHex)
	if err != nil {
		return VectorFile{}, fmt.Errorf("phone key: %w", err)
	}
	phone, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), phoneBytes)
	if err != nil {
		return VectorFile{}, fmt.Errorf("phone key: %w", err)
	}

	walletDID := dimocrypto.FromSecp256k1(wallet.PubKey()).DIDKey()
	cliDID := dimocrypto.FromSecp256k1(cli.PubKey()).DIDKey()
	phoneDID, err := dimocrypto.EncodeDIDKey(&phone.PublicKey)
	if err != nil {
		return VectorFile{}, fmt.Errorf("phone did:key: %w", err)
	}

	alias := []string{"did:ethr:137:0x" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}
	noServices := func() map[string]Service { return map[string]Service{} }

	var cases []Vector
	cids := map[string]string{}
	add := func(name string, op *Operation) error {
		unsigned := op.ToUnsigned()
		payload, err := json.Marshal(unsigned)
		if err != nil {
			return fmt.Errorf("%s: marshal: %w", name, err)
		}
		cbor, err := MarshalDAGCBOR(unsigned)
		if err != nil {
			return fmt.Errorf("%s: cbor: %w", name, err)
		}
		cid, err := ComputeCID(op)
		if err != nil {
			return fmt.Errorf("%s: cid: %w", name, err)
		}
		var didStr string
		if op.IsGenesis() {
			if didStr, err = DeriveFromGenesis(op); err != nil {
				return fmt.Errorf("%s: did: %w", name, err)
			}
		}
		sig := signK1(wallet, payload)
		cids[name] = cid
		cases = append(cases, Vector{
			Name:                name,
			Unsigned:            *unsigned,
			PayloadHex:          hex.EncodeToString(payload),
			CBORHex:             hex.EncodeToString(cbor),
			DID:                 didStr,
			CID:                 cid,
			SignerDIDKey:        walletDID,
			SignerPrivateKeyHex: vectorWalletKeyHex,
			Sig:                 sig,
		})
		return nil
	}
	prev := func(name string) *string {
		c, ok := cids[name]
		if !ok {
			panic("vectors: unknown prev case " + name)
		}
		return &c
	}

	steps := []struct {
		name string
		op   func() *Operation
	}{
		{"genesis-wallet-only", func() *Operation {
			return &Operation{Type: OpTypeCreate, RotationKeys: []string{walletDID},
				VerificationMethods: map[string]string{"wallet": walletDID}, AlsoKnownAs: []string{}, Services: noServices()}
		}},
		{"genesis-wallet-r1-signing", func() *Operation {
			return &Operation{Type: OpTypeCreate, RotationKeys: []string{walletDID},
				VerificationMethods: map[string]string{"wallet": walletDID, "signing": phoneDID}, AlsoKnownAs: []string{}, Services: noServices()}
		}},
		{"genesis-wallet-k1-signing-alias", func() *Operation {
			return &Operation{Type: OpTypeCreate, RotationKeys: []string{walletDID},
				VerificationMethods: map[string]string{"wallet": walletDID, "signing": cliDID}, AlsoKnownAs: alias, Services: noServices()}
		}},
		{"update-add-device", func() *Operation {
			return &Operation{Type: OpTypeCreate, RotationKeys: []string{walletDID},
				VerificationMethods: map[string]string{"wallet": walletDID, "signing": phoneDID, "device-2": cliDID},
				AlsoKnownAs:         []string{}, Services: noServices(), Prev: prev("genesis-wallet-r1-signing")}
		}},
		{"update-remove-device", func() *Operation {
			return &Operation{Type: OpTypeCreate, RotationKeys: []string{walletDID},
				VerificationMethods: map[string]string{"wallet": walletDID, "device-2": cliDID},
				AlsoKnownAs:         []string{}, Services: noServices(), Prev: prev("update-add-device")}
		}},
		{"update-set-alias", func() *Operation {
			return &Operation{Type: OpTypeCreate, RotationKeys: []string{walletDID},
				VerificationMethods: map[string]string{"wallet": walletDID}, AlsoKnownAs: alias, Services: noServices(),
				Prev: prev("genesis-wallet-only")}
		}},
		{"genesis-services-escaping", func() *Operation {
			return &Operation{Type: OpTypeCreate, RotationKeys: []string{walletDID},
				VerificationMethods: map[string]string{"wallet": walletDID}, AlsoKnownAs: []string{},
				Services: map[string]Service{
					"a":   {Type: "x<y>&z", Endpoint: "https://e.example/p?a=1&b=2"},
					"bbb": {Type: "t", Endpoint: "https://e.example/\u2028\u2029"},
				}}
		}},
		{"tombstone", func() *Operation {
			return &Operation{Type: OpTypeTombstone, RotationKeys: []string{}, VerificationMethods: map[string]string{},
				AlsoKnownAs: []string{}, Services: noServices(), Prev: prev("update-remove-device")}
		}},
	}
	for _, s := range steps {
		if err := add(s.name, s.op()); err != nil {
			return VectorFile{}, err
		}
	}
	return VectorFile{Version: 1, Cases: cases}, nil
}

// signK1 signs data with secp256k1 over sha256(data), returning base64url
// (no padding) of r || s, 32 bytes each.
func signK1(priv *secp256k1.PrivateKey, data []byte) string {
	hash := sha256.Sum256(data)
	sig := dcrecdsa.Sign(priv, hash[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	out := make([]byte, 0, 64)
	out = append(out, rb[:]...)
	out = append(out, sb[:]...)
	return base64.RawURLEncoding.EncodeToString(out)
}
