package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const defaultTurnkeyBaseURL = "https://api.turnkey.com"

// turnkeyAPIKey is a Turnkey API key: a P-256 key pair.
type turnkeyAPIKey struct {
	priv      *ecdsa.PrivateKey
	publicHex string // compressed
}

// loadTurnkeyAPIKey reads a JSON {publicKey, privateKey} file. Errors never
// include key material.
func loadTurnkeyAPIKey(path string) (*turnkeyAPIKey, error) {
	data, err := readSecretFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Turnkey API key file: %w", err)
	}
	var f struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, errors.New("Turnkey API key file is not valid JSON {publicKey, privateKey}")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(f.PrivateKey, "0x"))
	if err != nil {
		return nil, errors.New("Turnkey API key file: privateKey is not hex")
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, errors.New("Turnkey API key file: privateKey is not a P-256 scalar")
	}
	return &turnkeyAPIKey{
		priv:      priv,
		publicHex: hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)),
	}, nil
}

// stamp returns the X-Stamp header value for body: base64url of
// {publicKey, scheme, signature}, the signature a DER ECDSA P-256 signature
// over SHA-256(body), hex-encoded.
func (k *turnkeyAPIKey) stamp(body []byte) (string, error) {
	h := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, h[:])
	if err != nil {
		return "", fmt.Errorf("stamp: %w", err)
	}
	b, err := json.Marshal(map[string]string{
		"publicKey": k.publicHex,
		"scheme":    "SIGNATURE_SCHEME_TK_API_P256",
		"signature": hex.EncodeToString(sig),
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// turnkeyHTTPClient is a minimal stamped client for the three activities
// dimocli needs.
type turnkeyHTTPClient struct {
	base         string
	key          *turnkeyAPIKey
	http         *http.Client
	pollInterval time.Duration
	pollAttempts int
}

func newTurnkeyHTTPClient(base string, key *turnkeyAPIKey) *turnkeyHTTPClient {
	if base == "" {
		base = defaultTurnkeyBaseURL
	}
	return &turnkeyHTTPClient{
		base: strings.TrimRight(base, "/"), key: key,
		http:         &http.Client{Timeout: 30 * time.Second},
		pollInterval: time.Second, pollAttempts: 30,
	}
}

func (c *turnkeyHTTPClient) post(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	stamp, err := c.key.stamp(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Stamp", stamp)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("turnkey %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("turnkey %s: %s: %s", path, resp.Status, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

type tkActivity struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint"`
	Result      struct {
		SignRawPayloadResult struct {
			R string `json:"r"`
			S string `json:"s"`
		} `json:"signRawPayloadResult"`
		CreateWalletAccountsResult struct {
			Addresses []string `json:"addresses"`
		} `json:"createWalletAccountsResult"`
	} `json:"result"`
}

type tkActivityResponse struct {
	Activity tkActivity `json:"activity"`
}

// submit posts an activity and follows it to a final status.
func (c *turnkeyHTTPClient) submit(ctx context.Context, path, org, actType string, params any) (*tkActivity, error) {
	var res tkActivityResponse
	err := c.post(ctx, path, map[string]any{
		"type":           actType,
		"timestampMs":    strconv.FormatInt(time.Now().UnixMilli(), 10),
		"organizationId": org,
		"parameters":     params,
	}, &res)
	if err != nil {
		return nil, err
	}
	act := res.Activity
	for i := 0; ; i++ {
		switch act.Status {
		case "ACTIVITY_STATUS_COMPLETED":
			return &act, nil
		case "ACTIVITY_STATUS_CONSENSUS_NEEDED":
			return nil, &ErrConsensusNeeded{ActivityID: act.ID, Fingerprint: act.Fingerprint}
		case "ACTIVITY_STATUS_CREATED", "ACTIVITY_STATUS_PENDING":
			if i >= c.pollAttempts {
				return nil, fmt.Errorf("turnkey activity %s still %s after %d polls", act.ID, act.Status, i)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.pollInterval):
			}
			var poll tkActivityResponse
			if err := c.post(ctx, "/public/v1/query/get_activity", map[string]string{
				"organizationId": org, "activityId": act.ID,
			}, &poll); err != nil {
				return nil, err
			}
			act = poll.Activity
		default:
			return nil, fmt.Errorf("turnkey activity %s ended %s", act.ID, act.Status)
		}
	}
}

type tkAccount struct {
	ID        string `json:"walletAccountId"`
	Address   string `json:"address"`
	Path      string `json:"path"`
	PublicKey string `json:"publicKey"`
}

func (a tkAccount) account() walletAccount {
	return walletAccount{ID: a.ID, Address: a.Address, Path: a.Path, PublicKey: a.PublicKey}
}

const (
	accountsPageSize = 100
	// maxAccountPages backstops the cursor loop.
	maxAccountPages = 1000
)

// ListWalletAccounts follows Turnkey's cursor (limit 100, after the last
// walletAccountId) until a short page comes back. The default page is 10.
func (c *turnkeyHTTPClient) ListWalletAccounts(ctx context.Context, org, walletID string) ([]walletAccount, error) {
	var out []walletAccount
	after := ""
	for page := 0; page < maxAccountPages; page++ {
		po := map[string]string{"limit": strconv.Itoa(accountsPageSize)}
		if after != "" {
			po["after"] = after
		}
		var res struct {
			Accounts []tkAccount `json:"accounts"`
		}
		if err := c.post(ctx, "/public/v1/query/list_wallet_accounts", map[string]any{
			"organizationId": org, "walletId": walletID, "paginationOptions": po,
		}, &res); err != nil {
			return nil, err
		}
		for _, a := range res.Accounts {
			out = append(out, a.account())
		}
		if len(res.Accounts) < accountsPageSize {
			return out, nil
		}
		next := res.Accounts[len(res.Accounts)-1].ID
		if next == "" {
			return nil, errors.New("turnkey returned a full page of accounts without ids to page on")
		}
		if next == after {
			return nil, errors.New("turnkey: wallet account paging did not advance")
		}
		after = next
	}
	return nil, errors.New("turnkey: wallet account paging did not advance")
}

func (c *turnkeyHTTPClient) GetWalletAccount(ctx context.Context, org, walletID, address string) (walletAccount, error) {
	return c.getWalletAccount(ctx, map[string]string{"organizationId": org, "walletId": walletID, "address": address})
}

func (c *turnkeyHTTPClient) GetWalletAccountAtPath(ctx context.Context, org, walletID, path string) (walletAccount, error) {
	return c.getWalletAccount(ctx, map[string]string{"organizationId": org, "walletId": walletID, "path": path})
}

func (c *turnkeyHTTPClient) getWalletAccount(ctx context.Context, body map[string]string) (walletAccount, error) {
	var res struct {
		Account tkAccount `json:"account"`
	}
	if err := c.post(ctx, "/public/v1/query/get_wallet_account", body, &res); err != nil {
		return walletAccount{}, err
	}
	return res.Account.account(), nil
}

func (c *turnkeyHTTPClient) CreateWalletAccount(ctx context.Context, org, walletID, path string) (string, error) {
	act, err := c.submit(ctx, "/public/v1/submit/create_wallet_accounts", org, "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
		map[string]any{
			"walletId": walletID,
			"accounts": []map[string]string{{
				"curve":         "CURVE_SECP256K1",
				"pathFormat":    "PATH_FORMAT_BIP32",
				"path":          path,
				"addressFormat": "ADDRESS_FORMAT_ETHEREUM",
			}},
		})
	if err != nil {
		return "", err
	}
	addrs := act.Result.CreateWalletAccountsResult.Addresses
	if len(addrs) != 1 || addrs[0] == "" {
		return "", fmt.Errorf("Turnkey returned %d addresses for one new account", len(addrs))
	}
	return addrs[0], nil
}

func (c *turnkeyHTTPClient) SignRawPayload(ctx context.Context, org, signWith, payload string) (string, string, error) {
	act, err := c.submit(ctx, "/public/v1/submit/sign_raw_payload", org, "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
		map[string]string{
			"signWith":     signWith,
			"payload":      payload,
			"encoding":     "PAYLOAD_ENCODING_TEXT_UTF8",
			"hashFunction": "HASH_FUNCTION_SHA256",
		})
	if err != nil {
		return "", "", err
	}
	res := act.Result.SignRawPayloadResult
	if res.R == "" || res.S == "" {
		return "", "", errors.New("Turnkey returned no signature")
	}
	return res.R, res.S, nil
}
