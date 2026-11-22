package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/DIMO-Network/did-directory/pkg/identity"
	"github.com/DIMO-Network/did-directory/pkg/signin"
)

// createOptions is everything runCreate reads from its flags.
type createOptions struct {
	Services   map[string]did.Service
	Aliases    []string
	Controller string
	// Org marks an org DID: it carries a #dimo_org commit signing key. With
	// OrgHost the host makes that key when the org registers there; OrgKey
	// names one the host already holds; with neither the CLI generates one.
	Org     bool
	OrgKey  string
	OrgHost string
	// Dauth is where the new org signs in to register on OrgHost.
	Dauth string
}

// createPlan is a genesis operation ready to sign, plus the private material
// the CLI has to keep for it.
type createPlan struct {
	Op *did.UnsignedOperation
	// Opening is the control opening of a controlled DID.
	Opening *control.Opening
	// OrgKey is the generated #dimo_org private key, nil when --org-key was
	// given or the host makes the key.
	OrgKey *ecdsa.PrivateKey
	// Register says the org registers on its host once the genesis lands, and
	// the #dimo_org key the host returns is published then.
	Register bool
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
	host := strings.TrimRight(opts.OrgHost, "/")
	if host != "" {
		services = withOrgHost(services, host)
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
	if host != "" && opts.OrgKey == "" {
		// The host makes the key at register: under ORG_SIGNER=kms it never
		// takes one, so a key generated here would be one nobody serving the org
		// holds (R7-F8).
		plan.Register = true
		return plan, nil
	}
	if opts.Org || opts.OrgKey != "" {
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
	org := fs.Bool("org", false, "create an org DID with a #dimo_org repository commit signing key (generated here unless --org-host or --org-key)")
	orgKey := fs.String("org-key", "", "did:key to publish as #dimo_org when the org host already holds the private half (implies --org)")
	orgHost := fs.String("org-host", "", "org host URL, published as the #dimo_org_host service entry; without --org-key the new org then signs in to --dauth, registers there, and publishes the #dimo_org key the host makes (implies --org)")
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL, where a new org signs in to register on --org-host")
	tk := bindTurnkeyFlags(fs)
	fs.Func("turnkey-index", "create the Turnkey account at m/44'/60'/0'/0/<i> rather than after the wallet's highest, which takes a listing of the wallet", func(v string) error {
		i, err := strconv.ParseUint(v, 10, 31)
		if err != nil {
			return errors.New("must be an account index from 0 to 2147483647")
		}
		idx := uint32(i)
		tk.Index = &idx
		return nil
	})
	fs.Parse(args)

	if err := tk.validate(); err != nil {
		fatal(err)
	}
	if err := tk.refuseUnlessCar(*controller != ""); err != nil {
		fatal(err)
	}

	opts := createOptions{
		Services:   map[string]did.Service{},
		Controller: *controller,
		Org:        *org,
		OrgKey:     *orgKey,
		OrgHost:    *orgHost,
		Dauth:      *dauth,
	}
	if err := parseServices(*service, opts.Services); err != nil {
		fatal(err)
	}
	if *alias != "" {
		opts.Aliases = strings.Split(*alias, ",")
	}

	// The rotation key: a new account of the Turnkey wallet (the org root for
	// --org, the custody key for --controller), at --turnkey-index or the next
	// free index, else a new key that goes to the keystore: secp256k1 for an
	// org, the type of a Turnkey org root, P-256 otherwise. A controlled DID's
	// key only authorizes DID operations.
	ctx := context.Background()
	var signer opSigner
	if tk.enabled() {
		sg, err := tk.newSigner(ctx)
		if err != nil {
			fatal(err)
		}
		signer = sg
	} else {
		sg, err := localRootFor(opts)
		if err != nil {
			fatal(err)
		}
		signer = sg
	}

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	if _, err := executeCreate(ctx, c, opts, signer, os.Stdout); err != nil {
		fatal(err)
	}
}

// executeCreate builds, signs and submits the genesis operation, then keeps
// what the CLI has to keep: the keystore key when signer is a fileSigner
// (a Turnkey key is never copied out of Turnkey), the control opening, and a
// generated #dimo_org key. It returns the new DID.
func executeCreate(ctx context.Context, c *client.Client, opts createOptions, signer opSigner, out io.Writer) (string, error) {
	plan, err := buildCreate(opts, signer.DIDKey())
	if err != nil {
		return "", err
	}
	op, err := signOpWith(ctx, signer, plan.Op)
	if err != nil {
		return "", err
	}

	derivedDID, err := did.DeriveFromGenesis(op)
	if err != nil {
		return "", fmt.Errorf("deriving DID: %w", err)
	}

	resp, err := c.Submit(ctx, derivedDID, op)
	if err != nil {
		return "", fmt.Errorf("submitting operation: %w", err)
	}

	fmt.Fprintf(out, "DID created: %s\n", resp.DID)
	fmt.Fprintf(out, "CID: %s\n", resp.CID)
	if fsg, ok := signer.(*fileSigner); ok {
		if err := saveSigner(derivedDID, fsg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save key: %v\n", err)
		}
		fmt.Fprintf(out, "Key stored at: %s\n", keyFilePath(derivedDID))
	} else {
		fmt.Fprintf(out, "Key held in Turnkey: %s\n", signer.DIDKey())
	}

	if plan.Opening != nil {
		if err := SaveOpening(derivedDID, *plan.Opening); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save control opening: %v\n", err)
		}
		fmt.Fprintf(out, "Controller of record: %s (era 0, not published)\n", plan.Opening.Controller)
		fmt.Fprintf(out, "Control commitment: %s\n", *plan.Op.ControlCommitment)
		fmt.Fprintf(out, "Control opening stored at: %s\n", openingFilePath(derivedDID))
	}

	if orgDIDKey, ok := plan.Op.VerificationMethods[OrgKeyID]; ok {
		fmt.Fprintf(out, "Org commit key (#%s): %s\n", OrgKeyID, orgDIDKey)
		if plan.OrgKey != nil {
			if err := SaveOrgKey(derivedDID, plan.OrgKey); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save org key: %v\n", err)
			}
			fmt.Fprintf(out, "Org key stored at: %s\n", orgKeyFilePath(derivedDID))
		}
	}
	host, ok := plan.Op.Services[OrgHostServiceID]
	if ok {
		fmt.Fprintf(out, "Org host (#%s): %s\n", OrgHostServiceID, host.Endpoint)
	}
	if !plan.Register {
		return derivedDID, nil
	}

	// The DID now names the host, which register checks: sign in as the org,
	// register, and publish the key the host made.
	finish := fmt.Sprintf("register it on %s and publish the key it returns with: dimocli update --did %s --org-key <key>", host.Endpoint, derivedDID)
	orgDIDKey, err := registerOnHost(ctx, opts.Dauth, host.Endpoint, derivedDID, signer)
	if err != nil {
		return derivedDID, fmt.Errorf("%s was created, but registering it on its org host failed: %w; to finish, %s", derivedDID, err, finish)
	}
	upd, err := buildUpdate(op, resp.CID, updateOptions{OrgKey: orgDIDKey})
	if err != nil {
		return derivedDID, err
	}
	published, err := signOpWith(ctx, signer, upd.Op)
	if err != nil {
		return derivedDID, fmt.Errorf("%s is registered on %s with key %s, but signing the update that publishes it failed: %w; to finish, run dimocli update --did %s --org-key %s",
			derivedDID, host.Endpoint, orgDIDKey, err, derivedDID, orgDIDKey)
	}
	updated, err := c.Submit(ctx, derivedDID, published)
	if err != nil {
		return derivedDID, fmt.Errorf("%s is registered on %s with key %s, but publishing it failed: %w; to finish, run dimocli update --did %s --org-key %s",
			derivedDID, host.Endpoint, orgDIDKey, err, derivedDID, orgDIDKey)
	}
	fmt.Fprintf(out, "Registered on %s\n", host.Endpoint)
	fmt.Fprintf(out, "Org commit key (#%s, made by the host): %s\n", OrgKeyID, orgDIDKey)
	fmt.Fprintf(out, "CID: %s\n", updated.CID)
	return derivedDID, nil
}

// registerOnHost signs in to dauth as the org, for host with scope approve,
// and registers the org there with no key of its own: the host makes the
// #dimo_org key (in KMS, or sealed under its master key) and returns its
// did:key. The token is bound to a fresh P-256 key, whatever the root is.
func registerOnHost(ctx context.Context, dauth, host, org string, signer opSigner) (string, error) {
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	t, err := signin.SignIn(ctx, signin.Request{
		Dauth: dauth, DID: org, Signer: signer.Sign, DPoPKey: dpopKey, KeyFragment: "signing",
		Audience: []string{host}, Scope: identity.ScopeApprove,
	})
	if err != nil {
		return "", fmt.Errorf("sign in to %s for %s: %w", dauth, host, err)
	}
	url := host + "/orgs/" + org
	proof, err := dpopProof(dpopKey, http.MethodPost, url, t.Token, time.Now())
	if err != nil {
		return "", err
	}
	var reg struct {
		DID string `json:"did"`
		Key string `json:"key"`
	}
	headers := map[string]string{"Authorization": dpop.TokenType + " " + t.Token, dpop.HeaderName: proof}
	if err := sendJSON(http.MethodPost, url, headers, map[string]any{}, &reg); err != nil {
		return "", fmt.Errorf("register on %s: %w", host, err)
	}
	if reg.DID != org {
		return "", fmt.Errorf("register on %s answered for %q, not %s", host, reg.DID, org)
	}
	if _, err := dimocrypto.DecodeDIDKey(reg.Key); err != nil {
		return "", fmt.Errorf("register on %s returned a key that is not a did:key: %w", host, err)
	}
	return reg.Key, nil
}
