package proof

import (
	"context"
	"fmt"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/control"
)

// OrgKeyID is the verification method fragment that carries an org's commit
// signing key: <did>#dimo_org.
const OrgKeyID = "dimo_org"

// Directory is what DirectoryAnchors reads from the DID directory:
// pkg/client.Client satisfies it.
type Directory interface {
	Resolve(ctx context.Context, did string) (*did.DIDDocument, error)
	Control(ctx context.Context, did string) (*control.State, error)
}

// DirectoryAnchors resolves the anchors for p from the directory: each org's
// current #dimo_org key from its DID document, and the vehicle's era log. It
// is what a verifier who does not take the host's word for either uses; the
// proof then verifies against what the directory says today.
//
// v1 orgs have one commit key at a time and the directory does not serve its
// history, so a proof whose commits predate a rotation of #dimo_org fails to
// verify against the directory until it does.
func DirectoryAnchors(ctx context.Context, dir Directory, p *Proof) (Anchors, error) {
	a := Anchors{Keys: map[string]string{}}
	orgs := map[string]bool{}
	for i := range p.Commits {
		orgs[p.Commits[i].DID] = true
	}
	for org := range orgs {
		doc, err := dir.Resolve(ctx, org)
		if err != nil {
			return Anchors{}, fmt.Errorf("resolve %s: %w", org, err)
		}
		key, ok := OrgKey(doc)
		if !ok {
			return Anchors{}, fmt.Errorf("%s publishes no #%s key", org, OrgKeyID)
		}
		a.Keys[org] = key
	}
	state, err := dir.Control(ctx, p.Vehicle)
	if err != nil {
		return Anchors{}, fmt.Errorf("control state of %s: %w", p.Vehicle, err)
	}
	a.Control = state
	return a, nil
}

// OrgKey returns the #dimo_org key of a DID document as a did:key.
func OrgKey(doc *did.DIDDocument) (string, bool) {
	for _, vm := range doc.VerificationMethod {
		if strings.HasSuffix(vm.ID, "#"+OrgKeyID) && vm.PublicKeyMultibase != "" {
			return "did:key:" + vm.PublicKeyMultibase, true
		}
	}
	return "", false
}
