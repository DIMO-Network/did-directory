package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
)

// createOptions is everything runCreate reads from its flags.
type createOptions struct {
	Services   map[string]did.Service
	Aliases    []string
	Controller string
	// Org marks an org DID: it carries a #dimo_org commit signing key, generated
	// here unless OrgKey names one the org host already holds.
	Org     bool
	OrgKey  string
	OrgHost string
}

// createPlan is a genesis operation ready to sign, plus the private material
// the CLI has to keep for it.
type createPlan struct {
	Op *did.UnsignedOperation
	// Opening is the control opening of a controlled DID.
	Opening *control.Opening
	// OrgKey is the generated #dimo_org private key, nil when --org-key was given.
	OrgKey *ecdsa.PrivateKey
}

// buildCreate turns the options into an unsigned genesis operation whose
// rotation key is rotationKey.
func buildCreate(opts createOptions, rotationKey string) (*createPlan, error) {
	if opts.Controller != "" && (opts.Org || opts.OrgKey != "" || opts.OrgHost != "") {
		return nil, errors.New("a controlled DID cannot be an org: it has no verification methods")
	}

	services := opts.Services
	if services == nil {
		services = map[string]did.Service{}
	}
	if opts.OrgHost != "" {
		services = withOrgHost(services, opts.OrgHost)
	}

	plan := &createPlan{Op: &did.UnsignedOperation{
		Type:         did.OpTypeCreate,
		RotationKeys: []string{rotationKey},
		AlsoKnownAs:  opts.Aliases,
		Services:     services,
		Prev:         nil,
	}}

	if opts.Controller != "" {
		if !did.IsValidDID(opts.Controller) {
			return nil, fmt.Errorf("invalid --controller: %s", opts.Controller)
		}
		o, commitment, err := newCommitment(opts.Controller, 0)
		if err != nil {
			return nil, fmt.Errorf("create control commitment: %w", err)
		}
		plan.Op.ControlCommitment = &commitment
		plan.Opening = &o
		return plan, nil
	}

	plan.Op.VerificationMethods = map[string]string{"signing": rotationKey}
	if opts.Org || opts.OrgKey != "" || opts.OrgHost != "" {
		didKey, priv, err := resolveOrgKey(orgKeyChoice{Given: opts.OrgKey, Generate: true})
		if err != nil {
			return nil, err
		}
		plan.Op.VerificationMethods = withOrgKey(plan.Op.VerificationMethods, didKey)
		plan.OrgKey = priv
	}
	return plan, nil
}

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	service := fs.String("service", "", "service endpoints as id=type:endpoint (comma-separated)")
	alias := fs.String("alias", "", "also-known-as aliases (comma-separated)")
	controller := fs.String("controller", "", "controller of record DID; creates a controlled asset DID (e.g., a vehicle) with no signing key")
	org := fs.Bool("org", false, "create an org DID with a #dimo_org repository commit signing key")
	orgKey := fs.String("org-key", "", "did:key to publish as #dimo_org when the org host already holds the private half (implies --org)")
	orgHost := fs.String("org-host", "", "org host URL, published as the #dimo_org_host service entry (implies --org)")
	fs.Parse(args)

	// Generate a P-256 private key. For a controlled DID this is the per-vehicle
	// custody key held by the controller; it only authorizes DID operations.
	privKey, didKey, err := newKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := createOptions{
		Services:   map[string]did.Service{},
		Controller: *controller,
		Org:        *org,
		OrgKey:     *orgKey,
		OrgHost:    *orgHost,
	}
	if err := parseServices(*service, opts.Services); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if *alias != "" {
		opts.Aliases = strings.Split(*alias, ",")
	}

	plan, err := buildCreate(opts, didKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	op, err := signOp(privKey, plan.Op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Derive the DID.
	derivedDID, err := did.DeriveFromGenesis(op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving DID: %v\n", err)
		os.Exit(1)
	}

	// Submit to directory.
	c := client.New(*server)
	c.SetVerbose(isVerbose())
	resp, err := c.Submit(context.Background(), derivedDID, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting operation: %v\n", err)
		os.Exit(1)
	}

	// Save key to keystore.
	if err := SaveKey(derivedDID, privKey); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save key: %v\n", err)
	}

	fmt.Printf("DID created: %s\n", resp.DID)
	fmt.Printf("CID: %s\n", resp.CID)
	fmt.Printf("Key stored at: %s\n", keyFilePath(derivedDID))

	if plan.Opening != nil {
		if err := SaveOpening(derivedDID, *plan.Opening); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save control opening: %v\n", err)
		}
		fmt.Printf("Controller of record: %s (era 0, not published)\n", plan.Opening.Controller)
		fmt.Printf("Control commitment: %s\n", *plan.Op.ControlCommitment)
		fmt.Printf("Control opening stored at: %s\n", openingFilePath(derivedDID))
	}

	if orgDIDKey, ok := plan.Op.VerificationMethods[OrgKeyID]; ok {
		fmt.Printf("Org commit key (#%s): %s\n", OrgKeyID, orgDIDKey)
		if plan.OrgKey != nil {
			if err := SaveOrgKey(derivedDID, plan.OrgKey); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save org key: %v\n", err)
			}
			fmt.Printf("Org key stored at: %s\n", orgKeyFilePath(derivedDID))
		}
	}
	if host, ok := plan.Op.Services[OrgHostServiceID]; ok {
		fmt.Printf("Org host (#%s): %s\n", OrgHostServiceID, host.Endpoint)
	}
}
