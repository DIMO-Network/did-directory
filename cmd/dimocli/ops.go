package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
)

// signOp signs an unsigned operation and returns the signed operation.
func signOp(key *ecdsa.PrivateKey, unsigned *did.UnsignedOperation) (*did.Operation, error) {
	data, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("marshal operation: %w", err)
	}
	sig, err := dimocrypto.SignOperation(key, data)
	if err != nil {
		return nil, fmt.Errorf("sign operation: %w", err)
	}
	return &did.Operation{
		Type:                unsigned.Type,
		RotationKeys:        unsigned.RotationKeys,
		VerificationMethods: unsigned.VerificationMethods,
		AlsoKnownAs:         unsigned.AlsoKnownAs,
		Services:            unsigned.Services,
		ControlCommitment:   unsigned.ControlCommitment,
		EffectiveAt:         unsigned.EffectiveAt,
		RevokeSince:         unsigned.RevokeSince,
		Prev:                unsigned.Prev,
		Sig:                 sig,
	}, nil
}

// newKey generates a P-256 key and its did:key encoding.
func newKey() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("encode did:key: %w", err)
	}
	return key, didKey, nil
}

// newCommitment creates a fresh opening and commitment for controller at era.
func newCommitment(controller string, era uint64) (control.Opening, string, error) {
	salt, err := control.NewSalt()
	if err != nil {
		return control.Opening{}, "", err
	}
	opening := control.Opening{Controller: controller, Era: era, Salt: salt}
	commitment, err := control.Commit(opening)
	if err != nil {
		return control.Opening{}, "", err
	}
	return opening, commitment, nil
}

// currentEra returns the controlled DID's current era or an error if the DID is
// not controlled.
func currentEra(ctx context.Context, c *client.Client, didStr string) (*control.Era, error) {
	state, err := c.Control(ctx, didStr)
	if err != nil {
		return nil, err
	}
	cur := state.Current()
	if cur == nil {
		return nil, fmt.Errorf("%s is not a controlled DID", didStr)
	}
	return cur, nil
}
