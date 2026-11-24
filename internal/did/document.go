package did

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/control"
)

// DIDDocument represents a W3C DID Document.
type DIDDocument struct {
	Context            []string                  `json:"@context"`
	ID                 string                    `json:"id"`
	AlsoKnownAs        []string                  `json:"alsoKnownAs"`
	VerificationMethod []VerificationMethodEntry `json:"verificationMethod"`
	Service            []ServiceEntry            `json:"service,omitempty"`
	DimoControl        *ControlSummary           `json:"dimoControl,omitempty"`
}

// ControlSummary is the current control era of a controlled DID. The full era
// history is served at GET /:did/control.
type ControlSummary struct {
	Era               uint64               `json:"era"`
	EraStart          *time.Time           `json:"eraStart"`
	ControlCommitment string               `json:"controlCommitment"`
	Revocations       []control.Revocation `json:"revocations,omitempty"`
}

// VerificationMethodEntry represents a verification method in a DID Document.
type VerificationMethodEntry struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// ServiceEntry represents a service endpoint in a DID Document.
type ServiceEntry struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// ErrDeactivated is wrapped by GenerateDocument's error for a tombstoned DID.
// Any other error means the state does not make a document (a verification
// method that does not decode), which is not deactivation.
var ErrDeactivated = errors.New("deactivated")

// GenerateDocument generates a W3C DID Document from the current DID state.
// state may be nil for uncontrolled DIDs.
func GenerateDocument(did string, op *Operation, state *control.State) (*DIDDocument, error) {
	if op.IsTombstone() {
		return nil, fmt.Errorf("DID %s has been %w", did, ErrDeactivated)
	}

	doc := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/multikey/v1",
			"https://w3id.org/security/suites/secp256k1-2019/v1",
			"https://schema.dimo.zone/did/v1",
		},
		ID:          did,
		AlsoKnownAs: op.AlsoKnownAs,
	}

	if doc.AlsoKnownAs == nil {
		doc.AlsoKnownAs = []string{}
	}

	if cur := state.Current(); cur != nil {
		doc.DimoControl = &ControlSummary{
			Era:               cur.Number,
			EraStart:          cur.Start,
			ControlCommitment: cur.Commitment,
			Revocations:       cur.Revocations,
		}
	}

	// Build verification methods. Ranging over the map directly would randomise
	// the order per resolve, which breaks any ETag or canonicalisation a relying
	// party applies to the document, so sort by fragment id.
	for _, vmID := range slices.Sorted(maps.Keys(op.VerificationMethods)) {
		didKey := op.VerificationMethods[vmID]
		pub, err := dimocrypto.DecodeDIDKey(didKey)
		if err != nil {
			return nil, fmt.Errorf("decode verification method %q: %w", vmID, err)
		}

		doc.VerificationMethod = append(doc.VerificationMethod, VerificationMethodEntry{
			ID:                 did + "#" + vmID,
			Type:               "Multikey",
			Controller:         did,
			PublicKeyMultibase: pub.Multibase(),
		})
	}

	// Build service endpoints, sorted by fragment id for the same reason.
	for _, svcID := range slices.Sorted(maps.Keys(op.Services)) {
		svc := op.Services[svcID]
		doc.Service = append(doc.Service, ServiceEntry{
			ID:              "#" + svcID,
			Type:            svc.Type,
			ServiceEndpoint: svc.Endpoint,
		})
	}

	return doc, nil
}
