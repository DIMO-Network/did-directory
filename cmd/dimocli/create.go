package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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
	// The DID now names the host, which register checks.
	if err := finishRegistration(ctx, c, opts.Dauth, derivedDID, op, resp.CID, signer, out); err != nil {
		return derivedDID, fmt.Errorf("%s was created, but %w", derivedDID, err)
	}
	return derivedDID, nil
}

// finishRegistration puts org, whose latest operation is current (at CID
// prevCID), on the host its #dimo_org_host names, and publishes the
// #dimo_org key the host holds unless current already does. It is what create
// --org-host runs after the genesis and what dimocli register runs to finish
// a run that failed, so every failure says to run dimocli register.
func finishRegistration(ctx context.Context, c *client.Client, dauth, org string, current *did.Operation, prevCID string, signer opSigner, out io.Writer) error {
	finish := "to finish, run: dimocli register --did " + org + " (with the same key flags)"
	host, ok := current.Services[OrgHostServiceID]
	if !ok || host.Endpoint == "" {
		return fmt.Errorf("%s names no org host; publish one with dimocli update --did %s --org-host <url>", org, org)
	}
	key, err := registerOnHost(ctx, dauth, host.Endpoint, org, signer)
	if err != nil {
		return fmt.Errorf("registering it on %s failed: %w; %s", host.Endpoint, err, finish)
	}
	if current.VerificationMethods[OrgKeyID] == key {
		fmt.Fprintf(out, "Registered on %s; %s already publishes its key (#%s): %s\n", host.Endpoint, org, OrgKeyID, key)
		return nil
	}
	upd, err := buildUpdate(current, prevCID, updateOptions{OrgKey: key})
	if err != nil {
		return err
	}
	published, err := signOpWith(ctx, signer, upd.Op)
	if err != nil {
		return fmt.Errorf("it is registered on %s with key %s, but signing the update that publishes the key failed: %w; %s", host.Endpoint, key, err, finish)
	}
	updated, err := c.Submit(ctx, org, published)
	if err != nil {
		return fmt.Errorf("it is registered on %s with key %s, but publishing the key failed: %w; %s", host.Endpoint, key, err, finish)
	}
	fmt.Fprintf(out, "Registered on %s\n", host.Endpoint)
	fmt.Fprintf(out, "Org commit key (#%s, made by the host): %s\n", OrgKeyID, key)
	fmt.Fprintf(out, "CID: %s\n", updated.CID)
	return nil
}

// maxRegisterRetryWait caps how long a 503's Retry-After is honoured.
const maxRegisterRetryWait = 30 * time.Second

// retryWait sleeps d or until ctx ends; tests replace it.
var retryWait = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// registerOnHost signs in to dauth as the org, for host with scopes read and
// approve, and registers the org there with no key of its own: the host makes
// the #dimo_org key (in KMS, or sealed under its master key) and returns its
// did:key. A 503 (a register the host asks to retry) is retried once after its
// Retry-After. A 409, an org already registered by an earlier run, reads the
// key back with GET /orgs/:org. The token is bound to a fresh P-256 key,
// whatever the root is, and every request carries a fresh proof from it.
func registerOnHost(ctx context.Context, dauth, host, org string, signer opSigner) (string, error) {
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	t, err := signin.SignIn(ctx, signin.Request{
		Dauth: dauth, DID: org, Signer: signer.Sign, DPoPKey: dpopKey, KeyFragment: "signing",
		Audience: []string{host}, Scope: identity.ScopeRead + " " + identity.ScopeApprove,
	})
	if err != nil {
		return "", fmt.Errorf("sign in to %s for %s: %w", dauth, host, err)
	}
	url := host + "/orgs/" + org
	call := func(method string, body []byte) (int, http.Header, []byte, error) {
		proof, err := dpopProof(dpopKey, method, url, t.Token, time.Now())
		if err != nil {
			return 0, nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("Authorization", dpop.TokenType+" "+t.Token)
		req.Header.Set(dpop.HeaderName, proof)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			return 0, nil, nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, resp.Header, data, err
	}

	status, header, data, err := call(http.MethodPost, []byte("{}"))
	if err == nil && status == http.StatusServiceUnavailable {
		wait := time.Second
		if n, perr := strconv.Atoi(header.Get("Retry-After")); perr == nil && n > 0 {
			wait = time.Duration(n) * time.Second
		}
		if wait > maxRegisterRetryWait {
			wait = maxRegisterRetryWait
		}
		if err := retryWait(ctx, wait); err != nil {
			return "", err
		}
		status, _, data, err = call(http.MethodPost, []byte("{}"))
	}
	if err == nil && status == http.StatusConflict {
		status, _, data, err = call(http.MethodGet, nil)
	}
	if err != nil {
		return "", fmt.Errorf("register on %s: %w", host, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("register on %s: %d %s: %s", host, status, http.StatusText(status), strings.TrimSpace(string(data)))
	}
	var reg struct {
		DID string `json:"did"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &reg); err != nil {
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

// executeRegister finishes putting an existing org DID on the org host its
// #dimo_org_host names: it registers there (or finds it registered) and
// publishes the host's key unless the DID already does. It is safe to run
// again.
func executeRegister(ctx context.Context, c *client.Client, tk *turnkeyFlags, didStr, dauth string, out io.Writer) error {
	prevCID, current, err := getLatestCIDAndOp(ctx, c, didStr)
	if err != nil {
		return fmt.Errorf("getting latest state: %w", err)
	}
	if current.IsControlled() {
		return errors.New("a controlled DID cannot be an org: it has no verification methods")
	}
	signer, err := resolveSigner(ctx, tk, didStr, current, purposeUpdate)
	if err != nil {
		return err
	}
	return finishRegistration(ctx, c, dauth, didStr, current, prevCID, signer, out)
}

// runRegister is dimocli register: the resume path of create --org-host.
func runRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "org DID to register on the host its #dimo_org_host names (required)")
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL, where the org signs in to register")
	tk := bindTurnkeyFlags(fs)
	fs.Parse(args)
	if *didStr == "" {
		fmt.Fprintln(os.Stderr, "Error: --did is required")
		os.Exit(1)
	}
	if err := tk.validate(); err != nil {
		fatal(err)
	}
	c := client.New(*server)
	c.SetVerbose(isVerbose())
	if err := executeRegister(context.Background(), c, tk, *didStr, *dauth, os.Stdout); err != nil {
		fatal(err)
	}
}
