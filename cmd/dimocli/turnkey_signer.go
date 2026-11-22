package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// turnkeyAPI is the part of Turnkey dimocli uses. Tests fake it.
type turnkeyAPI interface {
	// ListWalletAccounts returns the wallet's accounts with their public keys.
	ListWalletAccounts(ctx context.Context, org, walletID string) ([]walletAccount, error)
	// GetWalletAccount returns the account with the Ethereum address.
	GetWalletAccount(ctx context.Context, org, walletID, address string) (walletAccount, error)
	// CreateWalletAccount adds a secp256k1 Ethereum-format account at path
	// (CREATE_WALLET_ACCOUNTS).
	CreateWalletAccount(ctx context.Context, org, walletID, path string) error
	// SignRawPayload signs the UTF-8 payload with signWith, Turnkey hashing it
	// with SHA-256 (SIGN_RAW_PAYLOAD), and returns r and s as hex. It returns
	// *ErrConsensusNeeded when the activity waits for approval.
	SignRawPayload(ctx context.Context, org, signWith, payload string) (r, s string, err error)
}

// walletAccount is one HD wallet account.
type walletAccount struct {
	ID        string // walletAccountId, the pagination cursor
	Address   string
	Path      string
	PublicKey string // hex, compressed or uncompressed secp256k1
}

// ErrConsensusNeeded means the activity is waiting for other users to approve
// it (ACTIVITY_STATUS_CONSENSUS_NEEDED); approving needs the fingerprint.
type ErrConsensusNeeded struct {
	ActivityID  string
	Fingerprint string
}

func (e *ErrConsensusNeeded) Error() string {
	return fmt.Sprintf("waiting for approval: %s (activity %s)", e.Fingerprint, e.ActivityID)
}

// turnkeySigner signs with one wallet account.
//
// Signing mode: PAYLOAD_ENCODING_TEXT_UTF8 with HASH_FUNCTION_SHA256. The
// operation's signing payload is JSON, so Turnkey hashes exactly the bytes
// dimocrypto.SignOperation hashes. It is the mode accounts' signGenesisAsDimo
// uses by default. Every signature is checked against the account's did:key,
// so a wrong mode fails here and not at the directory.
type turnkeySigner struct {
	api      turnkeyAPI
	org      string
	signWith string // the account's address
	didKey   string
}

func newTurnkeySigner(api turnkeyAPI, org string, acct walletAccount) (*turnkeySigner, error) {
	k, err := accountDIDKey(acct)
	if err != nil {
		return nil, err
	}
	return &turnkeySigner{api: api, org: org, signWith: acct.Address, didKey: k}, nil
}

func (s *turnkeySigner) DIDKey() string { return s.didKey }

func (s *turnkeySigner) Sign(ctx context.Context, data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", errors.New("operation payload is not valid UTF-8")
	}
	r, sv, err := s.api.SignRawPayload(ctx, s.org, s.signWith, string(data))
	if err != nil {
		return "", err
	}
	sig, err := rsToSig(r, sv)
	if err != nil {
		return "", err
	}
	pub, err := dimocrypto.DecodeDIDKey(s.didKey)
	if err != nil {
		return "", err
	}
	if err := pub.Verify(data, sig); err != nil {
		return "", fmt.Errorf("Turnkey signature failed verification against %s: %w", s.didKey, err)
	}
	return sig, nil
}

// rsToSig joins Turnkey's r and s into base64url r||s. Turnkey returns each as
// hex without leading zero bytes, so each is left-padded to 64 hex characters,
// as accounts' rsToSig does.
func rsToSig(r, s string) (string, error) {
	pad := func(name, v string) (string, error) {
		if len(v) > 64 {
			return "", fmt.Errorf("%s is longer than 32 bytes", name)
		}
		return strings.Repeat("0", 64-len(v)) + v, nil
	}
	rp, err := pad("r", r)
	if err != nil {
		return "", err
	}
	sp, err := pad("s", s)
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(rp + sp)
	if err != nil {
		return "", fmt.Errorf("signature is not hex: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// accountDIDKey is the did:key of a wallet account's secp256k1 public key.
func accountDIDKey(a walletAccount) (string, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(a.PublicKey, "0x"))
	if err != nil {
		return "", fmt.Errorf("account %s: public key is not hex", a.Address)
	}
	pub, err := secp256k1.ParsePubKey(raw)
	if err != nil {
		return "", fmt.Errorf("account %s: %w", a.Address, err)
	}
	return didkey.FromSecp256k1(pub).DIDKey(), nil
}

var accountPath = regexp.MustCompile(`^m/44'/60'/0'/0/(\d+)$`)

// createNextAccount adds the account after the wallet's highest
// m/44'/60'/0'/0/<i> and returns it.
func createNextAccount(ctx context.Context, api turnkeyAPI, org, walletID string) (walletAccount, error) {
	accts, err := api.ListWalletAccounts(ctx, org, walletID)
	if err != nil {
		return walletAccount{}, err
	}
	next := 0
	for _, a := range accts {
		if m := accountPath.FindStringSubmatch(a.Path); m != nil {
			if i, err := strconv.Atoi(m[1]); err == nil && i+1 > next {
				next = i + 1
			}
		}
	}
	path := fmt.Sprintf("m/44'/60'/0'/0/%d", next)
	if err := api.CreateWalletAccount(ctx, org, walletID, path); err != nil {
		return walletAccount{}, err
	}
	// The create result carries only the address; list again for the key.
	accts, err = api.ListWalletAccounts(ctx, org, walletID)
	if err != nil {
		return walletAccount{}, err
	}
	for _, a := range accts {
		if a.Path == path {
			return a, nil
		}
	}
	return walletAccount{}, fmt.Errorf("account %s not found in wallet after creating it", path)
}

// ethAddress is the EIP-55 checksummed Ethereum address of pub, the address
// Turnkey gives the account.
func ethAddress(pub *secp256k1.PublicKey) string {
	h := sha3.NewLegacyKeccak256()
	h.Write(pub.SerializeUncompressed()[1:])
	addr := hex.EncodeToString(h.Sum(nil)[12:])
	h = sha3.NewLegacyKeccak256()
	h.Write([]byte(addr))
	sum := hex.EncodeToString(h.Sum(nil))
	out := []byte(addr)
	for i, c := range out {
		if c >= 'a' && c <= 'f' && sum[i] >= '8' {
			out[i] = c - 'a' + 'A'
		}
	}
	return "0x" + string(out)
}

// addressOfDIDKey is the Ethereum address of a secp256k1 did:key.
func addressOfDIDKey(didKey string) (string, error) {
	pub, err := didkey.Decode(didKey)
	if err != nil {
		return "", err
	}
	k, err := secp256k1.ParsePubKey(pub.Compressed())
	if err != nil {
		return "", fmt.Errorf("%s is not a secp256k1 did:key", didKey)
	}
	return ethAddress(k), nil
}
