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
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

// fileSigner signs with a key from the local keystore: key, a P-256 key, or
// k1, a secp256k1 org root.
type fileSigner struct {
	key    *ecdsa.PrivateKey
	k1     *secp256k1.PrivateKey
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
	if s.k1 != nil {
		return signSecp256k1(s.k1, data), nil
	}
	return dimocrypto.SignOperation(s.key, data)
}

// signPurpose is what a resolved signer is about to authorize.
type signPurpose int

const (
	purposeUpdate signPurpose = iota
	purposeTransfer
	purposeRevoke
)

const errOnboardingSignin = "the onboarding credential can't sign in as an org"

const errOnboardingRefused = "the onboarding credential can't sign transfers or revocations"

const errOnboardingCarsOnly = "the onboarding credential can only sign car DIDs"

// turnkeyFlags are the flags that select Turnkey over the file keystore.
type turnkeyFlags struct {
	Org    string
	Wallet string
	// APIKey is the batch-scoped onboarding user's credential: it can create
	// accounts and sign in the fleet wallet, and dimocli lets it sign only car
	// (controlled) DIDs, and never a transfer or a revocation (decision 13).
	APIKey string
	// AdminAPIKey is an unrestricted credential for the same sub-org.
	AdminAPIKey string
	BaseURL     string
	// Index, when set, is the account index a new key is created at
	// (m/44'/60'/0'/0/<Index>), so the wallet is not listed for the next one.
	Index *uint32

	// api replaces the HTTP client; tests set it.
	api turnkeyAPI
}

func bindTurnkeyFlags(fs *flag.FlagSet) *turnkeyFlags {
	t := &turnkeyFlags{}
	fs.StringVar(&t.Org, "turnkey-org", "", "Turnkey sub-organization id holding the key")
	fs.StringVar(&t.Wallet, "turnkey-wallet", "", "Turnkey wallet id: new keys are its next account")
	fs.StringVar(&t.APIKey, "turnkey-api-key", "", "path to the batch-scoped onboarding user's API key JSON {publicKey, privateKey}; it signs car DIDs only, and no transfers or revocations")
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
		if t.Index != nil {
			return errors.New("--turnkey-index needs --turnkey-org, --turnkey-wallet and a Turnkey credential")
		}
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

// refuseOnboarding fails with msg when the credential is the onboarding one.
func (t *turnkeyFlags) refuseOnboarding(msg string) error {
	if t.enabled() && t.onboarding() {
		return errors.New(msg)
	}
	return nil
}

// refuseSensitive is the transfer and revocation guard.
func (t *turnkeyFlags) refuseSensitive() error { return t.refuseOnboarding(errOnboardingRefused) }

// refuseUnlessCar is the create, rotate and update guard: the onboarding
// credential signs car (controlled) DIDs only, never an org's or a person's.
func (t *turnkeyFlags) refuseUnlessCar(isCar bool) error {
	if isCar {
		return nil
	}
	return t.refuseOnboarding(errOnboardingCarsOnly)
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

// newSigner provisions a new wallet account, at Index or the wallet's next
// index, and returns a signer for it.
func (t *turnkeyFlags) newSigner(ctx context.Context) (*turnkeySigner, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	api, err := t.client()
	if err != nil {
		return nil, err
	}
	acct, err := createAccount(ctx, api, t.Org, t.Wallet, t.Index)
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
		s, err := loadSigner(didStr)
		if err != nil {
			return nil, fmt.Errorf("loading key: %w", err)
		}
		return s, nil
	}
	if purpose != purposeUpdate {
		if err := tk.refuseSensitive(); err != nil {
			return nil, err
		}
	}
	if err := tk.refuseUnlessCar(current.IsControlled()); err != nil {
		return nil, err
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
