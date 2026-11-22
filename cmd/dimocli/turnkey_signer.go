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
	// GetWalletAccountAtPath returns the account at the BIP-32 path.
	GetWalletAccountAtPath(ctx context.Context, org, walletID, path string) (walletAccount, error)
	// CreateWalletAccount adds a secp256k1 Ethereum-format account at path
	// (CREATE_WALLET_ACCOUNTS) and returns the address Turnkey derived for it.
	CreateWalletAccount(ctx context.Context, org, walletID, path string) (address string, err error)
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

func accountPathAt(index uint64) string { return fmt.Sprintf("m/44'/60'/0'/0/%d", index) }

// nextAccountIndex is one more than the wallet's highest m/44'/60'/0'/0/<i>,
// from one listing of the wallet.
func nextAccountIndex(ctx context.Context, api turnkeyAPI, org, walletID string) (uint64, error) {
	accts, err := api.ListWalletAccounts(ctx, org, walletID)
	if err != nil {
		return 0, err
	}
	var next uint64
	for _, a := range accts {
		if m := accountPath.FindStringSubmatch(a.Path); m != nil {
			if i, err := strconv.ParseUint(m[1], 10, 31); err == nil && i+1 > next {
				next = i + 1
			}
		}
	}
	return next, nil
}

// createAccount adds the account at m/44'/60'/0'/0/<index>, or after the
// wallet's highest index when index is nil, and returns it. A batch that
// passes the index per car never lists the wallet; without one, each car costs
// one listing. The new key is read by the address the create returned.
func createAccount(ctx context.Context, api turnkeyAPI, org, walletID string, index *uint32) (walletAccount, error) {
	var path string
	if index != nil {
		path = accountPathAt(uint64(*index))
	} else {
		next, err := nextAccountIndex(ctx, api, org, walletID)
		if err != nil {
			return walletAccount{}, err
		}
		path = accountPathAt(next)
	}
	addr, err := api.CreateWalletAccount(ctx, org, walletID, path)
	if err != nil {
		// Turnkey refuses a path the wallet holds; say so plainly, without
		// depending on the wording of its error.
		var cn *ErrConsensusNeeded
		if index != nil && !errors.As(err, &cn) {
			if _, gerr := api.GetWalletAccountAtPath(ctx, org, walletID, path); gerr == nil {
				return walletAccount{}, fmt.Errorf("account index %d already exists", *index)
			}
		}
		return walletAccount{}, err
	}
	acct, err := api.GetWalletAccount(ctx, org, walletID, addr)
	if err != nil {
		return walletAccount{}, fmt.Errorf("read the new account %s: %w", addr, err)
	}
	if acct.Path != path {
		return walletAccount{}, fmt.Errorf("Turnkey's account %s is at %s, not %s", addr, acct.Path, path)
	}
	return acct, nil
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
