// Package operation is the part of a DID's operation log a client outside
// this module needs: the operation types, how one is signed, and how a DID
// and a CID are derived from one. dimocli has the same logic over the
// internal packages; a service that holds keys for others (a console) uses
// this.
package operation

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
)

const (
	TypeCreate      = did.OpTypeCreate
	TypeTransfer    = did.OpTypeTransfer
	TypeRevokeSince = did.OpTypeRevokeSince
	TypeTombstone   = did.OpTypeTombstone
)

// The verification method and service an org publishes for its repository.
const (
	OrgKeyID           = "dimo_org"
	OrgHostServiceID   = "dimo_org_host"
	OrgHostServiceType = "DimoOrgHost"
)

type (
	Operation = did.Operation
	Unsigned  = did.UnsignedOperation
	Service   = did.Service
	Document  = did.DIDDocument
)

// Sign signs an operation with a rotation key of the DID it is for.
func Sign(key *ecdsa.PrivateKey, u *Unsigned) (*Operation, error) {
	data, err := json.Marshal(u)
	if err != nil {
		return nil, fmt.Errorf("marshal operation: %w", err)
	}
	sig, err := SignBytes(key, data)
	if err != nil {
		return nil, fmt.Errorf("sign operation: %w", err)
	}
	return &Operation{
		Type:                u.Type,
		RotationKeys:        u.RotationKeys,
		VerificationMethods: u.VerificationMethods,
		AlsoKnownAs:         u.AlsoKnownAs,
		Services:            u.Services,
		ControlCommitment:   u.ControlCommitment,
		EffectiveAt:         u.EffectiveAt,
		RevokeSince:         u.RevokeSince,
		Prev:                u.Prev,
		Sig:                 sig,
	}, nil
}

// SignBytes is the signature every DID-keyed act uses: ECDSA over SHA-256,
// base64url r||s. It signs operations, sign-in challenges and ES256 JWS
// signing inputs alike.
func SignBytes(key *ecdsa.PrivateKey, data []byte) (string, error) {
	return dimocrypto.SignOperation(key, data)
}

// DID derives the DID a genesis operation creates.
func DID(genesis *Operation) (string, error) { return did.DeriveFromGenesis(genesis) }

// CID is the identifier the next operation names as prev.
func CID(op *Operation) (string, error) { return did.ComputeCID(op) }

// ValidDID reports whether s is a did:dimo DID.
func ValidDID(s string) bool { return did.IsValidDID(s) }
