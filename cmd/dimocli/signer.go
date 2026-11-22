package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
)

// opSigner signs DID operations. The file keystore and Turnkey both
// implement it, so a command doesn't care where the key lives.
type opSigner interface {
	// DIDKey is the did:key of the signing key.
	DIDKey() string
	// Sign returns the base64url r||s signature over the SHA-256 of data, the
	// same bytes dimocrypto.SignOperation signs.
	Sign(ctx context.Context, data []byte) (string, error)
}

// fileSigner signs with a key from the local keystore.
type fileSigner struct {
	key    *ecdsa.PrivateKey
	didKey string
}

func newFileSigner(key *ecdsa.PrivateKey) (*fileSigner, error) {
	didKey, err := dimocrypto.EncodeDIDKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode did:key: %w", err)
	}
	return &fileSigner{key: key, didKey: didKey}, nil
}

// newFileSignerNew generates a fresh P-256 key.
func newFileSignerNew() (*fileSigner, error) {
	key, _, err := newKey()
	if err != nil {
		return nil, err
	}
	return newFileSigner(key)
}

func (s *fileSigner) DIDKey() string { return s.didKey }

func (s *fileSigner) Sign(_ context.Context, data []byte) (string, error) {
	return dimocrypto.SignOperation(s.key, data)
}

// signPurpose is what a resolved signer is about to authorize.
type signPurpose int

const (
	purposeUpdate signPurpose = iota
	purposeTransfer
	purposeRevoke
)

const errOnboardingRefused = "the onboarding credential can't sign transfers or revocations"

// turnkeyFlags are the flags that select Turnkey over the file keystore.
type turnkeyFlags struct {
	Org    string
	Wallet string
	// APIKey is the batch-scoped onboarding user's credential: it can create
	// accounts and sign in the fleet wallet, and dimocli never lets it sign a
	// transfer or a revocation (decision 13).
	APIKey string
	// AdminAPIKey is an unrestricted credential for the same sub-org.
	AdminAPIKey string
	BaseURL     string

	// api replaces the HTTP client; tests set it.
	api turnkeyAPI
}

func bindTurnkeyFlags(fs *flag.FlagSet) *turnkeyFlags {
	t := &turnkeyFlags{}
	fs.StringVar(&t.Org, "turnkey-org", "", "Turnkey sub-organization id holding the key")
	fs.StringVar(&t.Wallet, "turnkey-wallet", "", "Turnkey wallet id: new keys are its next account")
	fs.StringVar(&t.APIKey, "turnkey-api-key", "", "path to the batch-scoped onboarding user's API key JSON {publicKey, privateKey}; it can't sign transfers or revocations")
	fs.StringVar(&t.AdminAPIKey, "turnkey-admin-api-key", "", "path to an unrestricted Turnkey API key JSON {publicKey, privateKey}")
	fs.StringVar(&t.BaseURL, "turnkey-base-url", defaultTurnkeyBaseURL, "Turnkey API base URL")
	return t
}

// enabled reports whether any Turnkey flag was given.
func (t *turnkeyFlags) enabled() bool {
	return t.Org != "" || t.Wallet != "" || t.APIKey != "" || t.AdminAPIKey != ""
}

func (t *turnkeyFlags) validate() error {
	if !t.enabled() {
		return nil
	}
	if t.Org == "" || t.Wallet == "" {
		return errors.New("--turnkey-org and --turnkey-wallet are both required with Turnkey")
	}
	if t.APIKey == "" && t.AdminAPIKey == "" {
		return errors.New("Turnkey needs --turnkey-api-key (onboarding) or --turnkey-admin-api-key")
	}
	if t.APIKey != "" && t.AdminAPIKey != "" {
		return errors.New("--turnkey-api-key and --turnkey-admin-api-key are mutually exclusive")
	}
	return nil
}

// onboarding reports whether the credential is the batch-scoped one.
func (t *turnkeyFlags) onboarding() bool { return t.APIKey != "" }

// refuseSensitive is the transfer and revocation guard.
func (t *turnkeyFlags) refuseSensitive() error {
	if t.enabled() && t.onboarding() {
		return errors.New(errOnboardingRefused)
	}
	return nil
}

func (t *turnkeyFlags) client() (turnkeyAPI, error) {
	if t.api != nil {
		return t.api, nil
	}
	path := t.AdminAPIKey
	if t.onboarding() {
		path = t.APIKey
	}
	key, err := loadTurnkeyAPIKey(path)
	if err != nil {
		return nil, err
	}
	return newTurnkeyHTTPClient(t.BaseURL, key), nil
}

// newSigner provisions the wallet's next account and returns a signer for it.
func (t *turnkeyFlags) newSigner(ctx context.Context) (*turnkeySigner, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	api, err := t.client()
	if err != nil {
		return nil, err
	}
	acct, err := createNextAccount(ctx, api, t.Org, t.Wallet)
	if err != nil {
		return nil, err
	}
	return newTurnkeySigner(api, t.Org, acct)
}

// existingSigner returns a signer for the wallet account whose did:key is didKey.
func (t *turnkeyFlags) existingSigner(ctx context.Context, didKey string) (*turnkeySigner, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	api, err := t.client()
	if err != nil {
		return nil, err
	}
	// Look the account up by its address: a fleet wallet holds thousands of
	// accounts, and listing them is paginated.
	addr, err := addressOfDIDKey(didKey)
	if err != nil {
		return nil, err
	}
	acct, err := api.GetWalletAccount(ctx, t.Org, t.Wallet, addr)
	if err != nil {
		return nil, fmt.Errorf("no account in Turnkey wallet %s holds %s: %w", t.Wallet, didKey, err)
	}
	if k, err := accountDIDKey(acct); err != nil || k != didKey {
		return nil, fmt.Errorf("no account in Turnkey wallet %s holds %s", t.Wallet, didKey)
	}
	return newTurnkeySigner(api, t.Org, acct)
}

// resolveSigner returns the signer for an existing DID's current rotation key:
// a Turnkey account when Turnkey flags are set, else the keystore key.
func resolveSigner(ctx context.Context, tk *turnkeyFlags, didStr string, current *did.Operation, purpose signPurpose) (opSigner, error) {
	if !tk.enabled() {
		key, err := LoadKey(didStr)
		if err != nil {
			return nil, fmt.Errorf("loading key: %w", err)
		}
		return newFileSigner(key)
	}
	if purpose != purposeUpdate {
		if err := tk.refuseSensitive(); err != nil {
			return nil, err
		}
	}
	if len(current.RotationKeys) == 0 {
		return nil, errors.New("the DID has no rotation key")
	}
	return tk.existingSigner(ctx, current.RotationKeys[0])
}

// newCustody provisions a custody key for a DID: Turnkey's next account, or a
// fresh file key whose private half save writes to the keystore.
func newCustody(ctx context.Context, tk *turnkeyFlags) (didKey string, save func(did string) error, err error) {
	if tk.enabled() {
		sg, err := tk.newSigner(ctx)
		if err != nil {
			return "", nil, err
		}
		return sg.DIDKey(), func(string) error { return nil }, nil
	}
	key, didKey, err := newKey()
	if err != nil {
		return "", nil, err
	}
	return didKey, func(d string) error { return SaveKey(d, key) }, nil
}

// fatal prints err and exits: code 3 when Turnkey is waiting for approval
// (the approver needs the fingerprint), 1 otherwise.
func fatal(err error) {
	var cn *ErrConsensusNeeded
	if errors.As(err, &cn) {
		fmt.Fprintln(os.Stderr, cn.Error())
		os.Exit(3)
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
