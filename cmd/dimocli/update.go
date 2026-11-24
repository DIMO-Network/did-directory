package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/multiformats/go-multicodec"
)

// updateOptions is everything runUpdate reads from its flags.
type updateOptions struct {
	Services string
	Aliases  string
	// OrgKey publishes the given did:key as #dimo_org; NewOrgKey generates one.
	OrgKey    string
	NewOrgKey bool
	OrgHost   string
	// SigningKey publishes the given did:key as #signing, for a key held
	// somewhere else (a KMS, an HSM). The rotation key does not change.
	SigningKey string
}

// updatePlan is a plc_operation update ready to sign, plus the generated
// #dimo_org private key when --new-org-key asked for one.
type updatePlan struct {
	Op     *did.UnsignedOperation
	OrgKey *ecdsa.PrivateKey
}

// buildUpdate applies the options on top of the current operation.
func buildUpdate(current *did.Operation, prevCID string, opts updateOptions) (*updatePlan, error) {
	services := make(map[string]did.Service, len(current.Services)+1)
	for k, v := range current.Services {
		services[k] = v
	}
	if err := parseServices(opts.Services, services); err != nil {
		return nil, err
	}
	if opts.OrgHost != "" {
		services = withOrgHost(services, opts.OrgHost)
	}

	aliases := current.AlsoKnownAs
	if opts.Aliases != "" {
		aliases = strings.Split(opts.Aliases, ",")
	}

	vms := current.VerificationMethods
	if opts.SigningKey != "" {
		if current.IsControlled() {
			return nil, errors.New("a controlled DID cannot carry #signing: it has no verification methods")
		}
		pub, err := dimocrypto.DecodeDIDKey(opts.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("--signing-key: %w", err)
		}
		if pub.Codec() != multicodec.P256Pub {
			return nil, errors.New("--signing-key must be a P-256 did:key: events are signed with ES256")
		}
		next := make(map[string]string, len(vms)+1)
		for k, v := range vms {
			next[k] = v
		}
		next["signing"] = opts.SigningKey
		vms = next
	}
	choice := orgKeyChoice{Given: opts.OrgKey, Generate: opts.NewOrgKey}
	var orgKey *ecdsa.PrivateKey
	if choice.wanted() {
		if current.IsControlled() {
			return nil, errors.New("a controlled DID cannot carry #dimo_org: it has no verification methods")
		}
		didKey, priv, err := resolveOrgKey(choice)
		if err != nil {
			return nil, err
		}
		vms = withOrgKey(vms, didKey)
		orgKey = priv
	}

	return &updatePlan{
		Op: &did.UnsignedOperation{
			Type:                did.OpTypeCreate,
			RotationKeys:        current.RotationKeys,
			VerificationMethods: vms,
			AlsoKnownAs:         aliases,
			Services:            services,
			ControlCommitment:   current.ControlCommitment,
			Prev:                &prevCID,
		},
		OrgKey: orgKey,
	}, nil
}

func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "DID to update (required)")
	service := fs.String("service", "", "service endpoints as id=type:endpoint (comma-separated)")
	alias := fs.String("alias", "", "also-known-as aliases (comma-separated)")
	orgKey := fs.String("org-key", "", "did:key to publish as #dimo_org (the org host holds the private half)")
	newOrgKey := fs.Bool("new-org-key", false, "generate a new #dimo_org commit signing key and store it in the keystore")
	orgHost := fs.String("org-host", "", "org host URL, published as the #dimo_org_host service entry")
	signingKey := fs.String("signing-key", "", "P-256 did:key to publish as #signing, when the private half is held elsewhere (a KMS)")
	tk := bindTurnkeyFlags(fs)
	fs.Parse(args)

	if *didStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --did is required\n")
		os.Exit(1)
	}
	if *orgKey != "" && *newOrgKey {
		fmt.Fprintf(os.Stderr, "Error: --org-key and --new-org-key are mutually exclusive\n")
		os.Exit(1)
	}

	if err := tk.validate(); err != nil {
		fatal(err)
	}

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	ctx := context.Background()

	// Get the latest CID from audit log.
	prevCID, currentOp, err := getLatestCIDAndOp(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest state: %v\n", err)
		os.Exit(1)
	}

	// The rotation key signs: from the keystore, or the Turnkey account that holds it.
	signer, err := resolveSigner(ctx, tk, *didStr, currentOp, purposeUpdate)
	if err != nil {
		fatal(err)
	}

	plan, err := buildUpdate(currentOp, prevCID, updateOptions{
		Services:   *service,
		Aliases:    *alias,
		OrgKey:     *orgKey,
		NewOrgKey:  *newOrgKey,
		OrgHost:    *orgHost,
		SigningKey: *signingKey,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	op, err := signOpWith(ctx, signer, plan.Op)
	if err != nil {
		fatal(err)
	}

	resp, err := c.Submit(ctx, *didStr, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting update: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("DID updated: %s\n", resp.DID)
	fmt.Printf("CID: %s\n", resp.CID)
	if plan.OrgKey != nil {
		if err := SaveOrgKey(*didStr, plan.OrgKey); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save org key: %v\n", err)
		}
		fmt.Printf("Org key stored at: %s\n", orgKeyFilePath(*didStr))
	}
	if *orgKey != "" || *newOrgKey {
		fmt.Printf("Org commit key (#%s): %s\n", OrgKeyID, plan.Op.VerificationMethods[OrgKeyID])
	}
	if *signingKey != "" {
		fmt.Printf("Signing key (#signing): %s\n", *signingKey)
	}
	if *orgHost != "" {
		fmt.Printf("Org host (#%s): %s\n", OrgHostServiceID, *orgHost)
	}
}

// getLatestCIDAndOp fetches the audit log and returns the latest CID and operation.
func getLatestCIDAndOp(ctx context.Context, c *client.Client, didStr string) (string, *did.Operation, error) {
	entries, err := c.AuditLog(ctx, didStr)
	if err != nil {
		return "", nil, fmt.Errorf("fetch audit log: %w", err)
	}
	if len(entries) == 0 {
		return "", nil, fmt.Errorf("no operations found for %s", didStr)
	}

	// Parse the last entry to get the CID and operation.
	var entry struct {
		CID       string        `json:"cid"`
		Operation did.Operation `json:"operation"`
	}
	if err := json.Unmarshal(entries[len(entries)-1], &entry); err != nil {
		return "", nil, fmt.Errorf("unmarshal audit entry: %w", err)
	}

	return entry.CID, &entry.Operation, nil
}
