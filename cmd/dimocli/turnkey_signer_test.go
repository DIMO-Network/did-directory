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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTurnkey is an in-memory wallet: it holds real secp256k1 keys so the
// signatures it returns verify against the did:keys it reports.
type fakeTurnkey struct {
	mu       sync.Mutex
	accounts []walletAccount
	keys     map[string]*secp256k1.PrivateKey // by address
	created  []string                         // paths created through the API
	signed   int
	gets     int
	lists    int      // ListWalletAccounts calls
	gotAddrs []string // the addresses GetWalletAccount was asked for
	// consensus makes every signing activity wait for approval.
	consensus *ErrConsensusNeeded
	// trim returns r and s with leading zero bytes stripped, as Turnkey does.
	trim bool
}

func newFakeTurnkey(t *testing.T, indexes ...int) *fakeTurnkey {
	t.Helper()
	f := &fakeTurnkey{keys: map[string]*secp256k1.PrivateKey{}}
	for _, i := range indexes {
		f.add(t, i)
	}
	return f
}

func (f *fakeTurnkey) add(t *testing.T, index int) walletAccount {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pub := priv.PubKey().SerializeCompressed()
	addr := ethAddress(priv.PubKey())
	a := walletAccount{
		ID:        "wa-" + addr,
		Address:   addr,
		Path:      fmt.Sprintf("m/44'/60'/0'/0/%d", index),
		PublicKey: hex.EncodeToString(pub),
	}
	f.keys[a.Address] = priv
	f.accounts = append(f.accounts, a)
	return a
}

func (f *fakeTurnkey) ListWalletAccounts(_ context.Context, _, _ string) ([]walletAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	return append([]walletAccount(nil), f.accounts...), nil
}

func (f *fakeTurnkey) GetWalletAccount(_ context.Context, _, _, address string) (walletAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	f.gotAddrs = append(f.gotAddrs, address)
	for _, a := range f.accounts {
		if a.Address == address {
			return a, nil
		}
	}
	return walletAccount{}, errors.New("no such account")
}

func (f *fakeTurnkey) GetWalletAccountAtPath(_ context.Context, _, _, path string) (walletAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	for _, a := range f.accounts {
		if a.Path == path {
			return a, nil
		}
	}
	return walletAccount{}, errors.New("no such account")
}

// CreateWalletAccount refuses a path the wallet already holds, as Turnkey does,
// with an error that does not say why: dimocli must not depend on its wording.
func (f *fakeTurnkey) CreateWalletAccount(_ context.Context, _, _, path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.accounts {
		if a.Path == path {
			return "", errors.New("turnkey activity a1 ended ACTIVITY_STATUS_FAILED")
		}
	}
	f.created = append(f.created, path)
	priv, _ := secp256k1.GeneratePrivateKey()
	pub := priv.PubKey().SerializeCompressed()
	addr := ethAddress(priv.PubKey())
	a := walletAccount{ID: "wa-" + addr, Address: addr, Path: path, PublicKey: hex.EncodeToString(pub)}
	f.keys[a.Address] = priv
	f.accounts = append(f.accounts, a)
	return addr, nil
}

func (f *fakeTurnkey) SignRawPayload(_ context.Context, _, signWith, payload string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consensus != nil {
		return "", "", f.consensus
	}
	priv, ok := f.keys[signWith]
	if !ok {
		return "", "", errors.New("no such account")
	}
	f.signed++
	h := sha256.Sum256([]byte(payload))
	sig := dcrecdsa.Sign(priv, h[:])
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	rr, ss := rb[:], sb[:]
	if f.trim {
		rr, ss = bytes.TrimLeft(rr, "\x00"), bytes.TrimLeft(ss, "\x00")
	}
	return hex.EncodeToString(rr), hex.EncodeToString(ss), nil
}

func (f *fakeTurnkey) didKeyAt(t *testing.T, path string) string {
	t.Helper()
	for _, a := range f.accounts {
		if a.Path == path {
			k, err := accountDIDKey(a)
			require.NoError(t, err)
			return k
		}
	}
	t.Fatalf("no account at %s", path)
	return ""
}

func tkFlags(api turnkeyAPI, onboarding bool) *turnkeyFlags {
	f := &turnkeyFlags{Org: "sub-org", Wallet: "wallet-1", api: api}
	if onboarding {
		f.APIKey = "unused"
	} else {
		f.AdminAPIKey = "unused"
	}
	return f
}

func verifyOp(t *testing.T, didKeyStr string, op *did.Operation) {
	t.Helper()
	unsigned := &did.UnsignedOperation{
		Type: op.Type, RotationKeys: op.RotationKeys, VerificationMethods: op.VerificationMethods,
		AlsoKnownAs: op.AlsoKnownAs, Services: op.Services, ControlCommitment: op.ControlCommitment,
		EffectiveAt: op.EffectiveAt, RevokeSince: op.RevokeSince, Prev: op.Prev,
	}
	data, err := json.Marshal(unsigned)
	require.NoError(t, err)
	pub, err := dimocrypto.DecodeDIDKey(didKeyStr)
	require.NoError(t, err)
	require.NoError(t, pub.Verify(data, op.Sig))
}

func TestTurnkeySigner_PadsA31ByteR(t *testing.T) {
	f := newFakeTurnkey(t, 0)
	f.trim = true
	sg, err := newTurnkeySigner(f, "sub-org", f.accounts[0])
	require.NoError(t, err)

	// Grind the payload until r (or s) has a leading zero byte.
	for i := 0; i < 5000; i++ {
		data := []byte(fmt.Sprintf(`{"n":%d}`, i))
		h := sha256.Sum256(data)
		sig := dcrecdsa.Sign(f.keys[f.accounts[0].Address], h[:])
		rs, ss := sig.R(), sig.S()
		r, s := rs.Bytes(), ss.Bytes()
		if r[0] != 0 && s[0] != 0 {
			continue
		}
		out, err := sg.Sign(context.Background(), data)
		require.NoError(t, err)
		raw, err := base64.RawURLEncoding.DecodeString(out)
		require.NoError(t, err)
		assert.Len(t, raw, 64, "r and s are each left-padded to 32 bytes")
		pub, err := dimocrypto.DecodeDIDKey(sg.DIDKey())
		require.NoError(t, err)
		require.NoError(t, pub.Verify(data, out), "did-directory's own verifier accepts it")
		return
	}
	t.Fatal("could not find a payload with a short r")
}

func TestRSToSig(t *testing.T) {
	sig, err := rsToSig("ab", "1")
	require.NoError(t, err)
	raw, _ := base64.RawURLEncoding.DecodeString(sig)
	require.Len(t, raw, 64)
	assert.Equal(t, byte(0xab), raw[31])
	assert.Equal(t, byte(0x01), raw[63])
	_, err = rsToSig(strings.Repeat("a", 66), "1")
	assert.Error(t, err)
}

func TestTurnkeySigner_ConsensusNeededIsReported(t *testing.T) {
	f := newFakeTurnkey(t, 0)
	f.consensus = &ErrConsensusNeeded{ActivityID: "act-9", Fingerprint: "fp-123"}
	sg, err := newTurnkeySigner(f, "sub-org", f.accounts[0])
	require.NoError(t, err)
	_, err = sg.Sign(context.Background(), []byte(`{}`))
	var cn *ErrConsensusNeeded
	require.ErrorAs(t, err, &cn)
	assert.Equal(t, "act-9", cn.ActivityID)
	assert.Equal(t, "fp-123", cn.Fingerprint)
	assert.Equal(t, "waiting for approval: fp-123 (activity act-9)", cn.Error())
}

func TestTurnkeyFlags_NewSignerTakesTheNextIndex(t *testing.T) {
	f := newFakeTurnkey(t, 0, 1, 5)
	sg, err := tkFlags(f, true).newSigner(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"m/44'/60'/0'/0/6"}, f.created)
	assert.Equal(t, f.didKeyAt(t, "m/44'/60'/0'/0/6"), sg.DIDKey())
	assert.True(t, strings.HasPrefix(sg.DIDKey(), "did:key:zQ3s"), "secp256k1 did:key")

	empty := newFakeTurnkey(t)
	_, err = tkFlags(empty, true).newSigner(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"m/44'/60'/0'/0/0"}, empty.created)
}

// directoryStub accepts every submission and records the operations.
func directoryStub(t *testing.T) (*client.Client, *[]*did.Operation) {
	t.Helper()
	var ops []*did.Operation
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var op did.Operation
		require.NoError(t, json.NewDecoder(r.Body).Decode(&op))
		ops = append(ops, &op)
		_, _ = w.Write([]byte(`{"did":"` + strings.TrimPrefix(r.URL.Path, "/") + `","cid":"bafyfake"}`))
	}))
	t.Cleanup(srv.Close)
	return client.New(srv.URL), &ops
}

func TestCreateControlled_TurnkeyWritesNoPrivateKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := newFakeTurnkey(t, 0)
	c, ops := directoryStub(t)

	sg, err := tkFlags(f, true).newSigner(context.Background())
	require.NoError(t, err)
	var out bytes.Buffer
	derived, err := executeCreate(context.Background(), c, createOptions{Controller: "did:dimo:avis"}, sg, &out)
	require.NoError(t, err)

	require.Len(t, *ops, 1)
	op := (*ops)[0]
	assert.Equal(t, []string{f.didKeyAt(t, "m/44'/60'/0'/0/1")}, op.RotationKeys, "the rotation key is the new account's did:key")
	verifyOp(t, op.RotationKeys[0], op)
	assert.Equal(t, 1, f.signed)

	entries, err := os.ReadDir(filepath.Join(home, ".dimo", "keys"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{strings.TrimPrefix(derived, "did:dimo:") + ".control.json"}, names,
		"only the control opening is saved")
}

func TestCreateOrg_TurnkeyRootIsTheNextAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeTurnkey(t)
	c, ops := directoryStub(t)
	sg, err := tkFlags(f, false).newSigner(context.Background())
	require.NoError(t, err)
	_, err = executeCreate(context.Background(), c, createOptions{Org: true}, sg, &bytes.Buffer{})
	require.NoError(t, err)
	op := (*ops)[0]
	root := f.didKeyAt(t, "m/44'/60'/0'/0/0")
	assert.Equal(t, []string{root}, op.RotationKeys)
	assert.Equal(t, root, op.VerificationMethods["signing"])
	assert.Contains(t, op.VerificationMethods, OrgKeyID)
	verifyOp(t, root, op)
}

func TestFileSigner_CreateStillSavesTheKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	c, ops := directoryStub(t)
	fsg, err := newFileSignerNew()
	require.NoError(t, err)
	derived, err := executeCreate(context.Background(), c, createOptions{Controller: "did:dimo:avis"}, fsg, &bytes.Buffer{})
	require.NoError(t, err)
	verifyOp(t, fsg.DIDKey(), (*ops)[0])
	_, err = LoadKey(derived)
	require.NoError(t, err)
}

func TestBuildRotateToTurnkey_OnlyRotationKeysAndSigningChange(t *testing.T) {
	_, root, err := newKey()
	require.NoError(t, err)
	_, orgKey, err := newKey()
	require.NoError(t, err)
	_, tk, err := newKey()
	require.NoError(t, err)
	current := &did.Operation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{root},
		VerificationMethods: map[string]string{"signing": root, OrgKeyID: orgKey},
		AlsoKnownAs:         []string{"at://avis"},
		Services:            map[string]did.Service{OrgHostServiceID: {Type: OrgHostServiceType, Endpoint: "https://h"}},
	}
	op := buildRotateTo(current, "cid1", tk)
	assert.Equal(t, []string{tk}, op.RotationKeys)
	assert.Equal(t, map[string]string{"signing": tk, OrgKeyID: orgKey}, op.VerificationMethods)
	assert.Equal(t, current.AlsoKnownAs, op.AlsoKnownAs)
	assert.Equal(t, current.Services, op.Services)
	assert.Equal(t, "cid1", *op.Prev)
	assert.Equal(t, root, current.VerificationMethods["signing"], "current is not mutated")

	// A #signing that is not the root stays put.
	_, other, _ := newKey()
	current.VerificationMethods["signing"] = other
	op = buildRotateTo(current, "cid1", tk)
	assert.Equal(t, other, op.VerificationMethods["signing"])
}

func TestResolveSigner_OnboardingCredentialRefusedForTransfersAndRevocations(t *testing.T) {
	f := newFakeTurnkey(t, 0)
	car := carOp(t, f.didKeyAt(t, "m/44'/60'/0'/0/0"))
	cur := &car

	_, err := resolveSigner(context.Background(), tkFlags(f, true), "did:dimo:v", cur, purposeTransfer)
	require.Error(t, err)
	assert.Equal(t, "the onboarding credential can't sign transfers or revocations", err.Error())
	_, err = resolveSigner(context.Background(), tkFlags(f, true), "did:dimo:v", cur, purposeRevoke)
	require.Error(t, err)
	assert.Equal(t, 0, f.signed)

	sg, err := resolveSigner(context.Background(), tkFlags(f, false), "did:dimo:v", cur, purposeTransfer)
	require.NoError(t, err)
	assert.Equal(t, cur.RotationKeys[0], sg.DIDKey())
	sg, err = resolveSigner(context.Background(), tkFlags(f, true), "did:dimo:v", cur, purposeUpdate)
	require.NoError(t, err)
	assert.Equal(t, cur.RotationKeys[0], sg.DIDKey())

	// An org's update is not the onboarding credential's to sign.
	org := orgOp(cur.RotationKeys[0])
	_, err = resolveSigner(context.Background(), tkFlags(f, true), "did:dimo:org", &org, purposeUpdate)
	require.Error(t, err)
	assert.Equal(t, errCarsOnly, err.Error())
	_, err = resolveSigner(context.Background(), tkFlags(f, false), "did:dimo:org", &org, purposeUpdate)
	require.NoError(t, err, "the admin credential still signs it")
}

func TestTurnkeyFlags_Validate(t *testing.T) {
	assert.NoError(t, (&turnkeyFlags{}).validate(), "no turnkey flags is the file keystore")
	assert.Error(t, (&turnkeyFlags{Org: "o"}).validate())
	assert.Error(t, (&turnkeyFlags{Org: "o", Wallet: "w"}).validate(), "needs a credential")
	assert.Error(t, (&turnkeyFlags{Org: "o", Wallet: "w", APIKey: "a", AdminAPIKey: "b"}).validate())
	assert.NoError(t, (&turnkeyFlags{Org: "o", Wallet: "w", APIKey: "a"}).validate())
}

// --- the HTTP client and the stamp ---

func writeAPIKey(t *testing.T) (path string, pub *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	raw, err := priv.Bytes()
	require.NoError(t, err)
	comp := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	b, _ := json.Marshal(map[string]string{"publicKey": hex.EncodeToString(comp), "privateKey": hex.EncodeToString(raw)})
	path = filepath.Join(t.TempDir(), "key.json")
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return path, &priv.PublicKey
}

func TestStamp_IsAVerifiableP256SignatureOverTheBody(t *testing.T) {
	path, pub := writeAPIKey(t)
	key, err := loadTurnkeyAPIKey(path)
	require.NoError(t, err)
	body := []byte(`{"organizationId":"o"}`)
	stamp, err := key.stamp(body)
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(stamp)
	require.NoError(t, err)
	var s struct{ PublicKey, Scheme, Signature string }
	require.NoError(t, json.Unmarshal(raw, &s))
	assert.Equal(t, "SIGNATURE_SCHEME_TK_API_P256", s.Scheme)
	assert.Equal(t, hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y)), s.PublicKey)
	sig, err := hex.DecodeString(s.Signature)
	require.NoError(t, err)
	h := sha256.Sum256(body)
	assert.True(t, ecdsa.VerifyASN1(pub, h[:], sig), "DER ECDSA over SHA-256 of the exact body")
}

func TestLoadTurnkeyAPIKey_NeverEchoesKeyMaterial(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.json")
	require.NoError(t, os.WriteFile(p, []byte(`{"publicKey":"02aa","privateKey":"SECRETSECRET"}`), 0o600))
	_, err := loadTurnkeyAPIKey(p)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRETSECRET")
}

// turnkeyHTTPStub speaks the three Turnkey endpoints dimocli uses.
var stubAfters []string // `after` cursors the list stub saw, reset by the tests that read it
var stubIgnoreAfter bool

func turnkeyHTTPStub(t *testing.T, f *fakeTurnkey, signStatus string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.Header.Get("X-Stamp"), "every request is stamped")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ctx := context.Background()
		switch r.URL.Path {
		case "/public/v1/query/list_wallet_accounts":
			// The fake counts calls; the stub counts pages, so read the accounts directly.
			f.mu.Lock()
			accts := append([]walletAccount(nil), f.accounts...)
			f.mu.Unlock()
			if po, _ := body["paginationOptions"].(map[string]any); po["after"] == nil {
				f.mu.Lock()
				f.lists++
				f.mu.Unlock()
			}
			// Turnkey pages: 10 by default, up to 100, after a walletAccountId cursor.
			limit, after := 10, ""
			if po, ok := body["paginationOptions"].(map[string]any); ok {
				if l, ok := po["limit"].(string); ok {
					limit, _ = strconv.Atoi(l)
				}
				after, _ = po["after"].(string)
			}
			if after != "" {
				stubAfters = append(stubAfters, after)
			}
			if stubIgnoreAfter {
				after = ""
			}
			assert.LessOrEqual(t, limit, 100)
			start := 0
			if after != "" {
				for i, a := range accts {
					if a.ID == after {
						start = i + 1
					}
				}
			}
			end := min(start+limit, len(accts))
			var out []map[string]string
			for _, a := range accts[start:end] {
				out = append(out, map[string]string{"walletAccountId": a.ID, "address": a.Address, "path": a.Path, "publicKey": a.PublicKey})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accounts": out})
		case "/public/v1/query/get_wallet_account":
			var a walletAccount
			var err error
			if path, ok := body["path"].(string); ok {
				a, err = f.GetWalletAccountAtPath(ctx, "", "", path)
			} else {
				a, err = f.GetWalletAccount(ctx, "", "", body["address"].(string))
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]string{"walletAccountId": a.ID, "address": a.Address, "path": a.Path, "publicKey": a.PublicKey}})
		case "/public/v1/submit/create_wallet_accounts":
			params := body["parameters"].(map[string]any)
			acct := params["accounts"].([]any)[0].(map[string]any)
			assert.Equal(t, "CURVE_SECP256K1", acct["curve"])
			assert.Equal(t, "ADDRESS_FORMAT_ETHEREUM", acct["addressFormat"])
			assert.Equal(t, "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS", body["type"])
			addr, err := f.CreateWalletAccount(ctx, "", "", acct["path"].(string))
			if err != nil {
				http.Error(w, `{"code":3,"message":"internal error"}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"activity": map[string]any{
				"id": "a1", "status": "ACTIVITY_STATUS_COMPLETED",
				"result": map[string]any{"createWalletAccountsResult": map[string]any{"addresses": []string{addr}}},
			}})
		case "/public/v1/submit/sign_raw_payload":
			params := body["parameters"].(map[string]any)
			assert.Equal(t, "PAYLOAD_ENCODING_TEXT_UTF8", params["encoding"])
			assert.Equal(t, "HASH_FUNCTION_SHA256", params["hashFunction"])
			if signStatus != "ACTIVITY_STATUS_COMPLETED" {
				_ = json.NewEncoder(w).Encode(map[string]any{"activity": map[string]any{"id": "act1", "status": signStatus, "fingerprint": "fp123"}})
				return
			}
			rr, ss, err := f.SignRawPayload(ctx, "", params["signWith"].(string), params["payload"].(string))
			require.NoError(t, err)
			_ = json.NewEncoder(w).Encode(map[string]any{"activity": map[string]any{
				"id": "a2", "status": "ACTIVITY_STATUS_COMPLETED",
				"result": map[string]any{"signRawPayloadResult": map[string]string{"r": rr, "s": ss}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPClient_EndToEndAgainstAStub(t *testing.T) {
	f := newFakeTurnkey(t, 0)
	srv := turnkeyHTTPStub(t, f, "ACTIVITY_STATUS_COMPLETED")
	keyPath, _ := writeAPIKey(t)
	tf := &turnkeyFlags{Org: "o", Wallet: "w", APIKey: keyPath, BaseURL: srv.URL}
	sg, err := tf.newSigner(context.Background())
	require.NoError(t, err)
	data := []byte(`{"type":"create"}`)
	sig, err := sg.Sign(context.Background(), data)
	require.NoError(t, err)
	pub, err := didkey.Decode(sg.DIDKey())
	require.NoError(t, err)
	require.NoError(t, pub.Verify(data, sig))
}

// --- the commands, as a user runs them ---

func TestDimocliMain(t *testing.T) {
	args := os.Getenv("DIMOCLI_TEST_ARGS")
	if args == "" {
		t.Skip("subprocess helper")
	}
	os.Args = append([]string{"dimocli"}, strings.Split(args, "\x1f")...)
	main()
	os.Exit(0)
}

func runDimocli(t *testing.T, args ...string) (stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDimocliMain$")
	cmd.Env = append(os.Environ(), "DIMOCLI_TEST_ARGS="+strings.Join(args, "\x1f"), "HOME="+t.TempDir())
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	if ee := (&exec.ExitError{}); errors.As(err, &ee) {
		return errb.String(), ee.ExitCode()
	}
	require.NoError(t, err)
	return errb.String(), 0
}

func TestCreate_ConsensusNeededExitsThreeWithoutHanging(t *testing.T) {
	f := newFakeTurnkey(t, 0)
	srv := turnkeyHTTPStub(t, f, "ACTIVITY_STATUS_CONSENSUS_NEEDED")
	keyPath, _ := writeAPIKey(t)
	stderr, code := runDimocli(t, "create", "--controller", "did:dimo:avis",
		"--turnkey-org", "o", "--turnkey-wallet", "w", "--turnkey-api-key", keyPath, "--turnkey-base-url", srv.URL,
		"--server", "http://127.0.0.1:1")
	assert.Equal(t, 3, code)
	assert.Contains(t, stderr, "waiting for approval: fp123 (activity act1)")
}

func TestTransferAndRevokeSince_RefuseTheOnboardingCredential(t *testing.T) {
	keyPath, _ := writeAPIKey(t)
	tk := []string{"--turnkey-org", "o", "--turnkey-wallet", "w", "--turnkey-api-key", keyPath}
	for _, cmd := range [][]string{
		append([]string{"transfer", "--did", "did:dimo:v", "--to", "did:dimo:b"}, tk...),
		append([]string{"revoke-since", "--did", "did:dimo:v", "--since", "2026-01-01T00:00:00Z"}, tk...),
	} {
		stderr, code := runDimocli(t, cmd...)
		assert.Equal(t, 1, code, cmd[0])
		assert.Contains(t, stderr, "the onboarding credential can't sign transfers or revocations", cmd[0])
	}
}

// A wallet of 250 accounts is three pages (100, 100, 50): the client must send
// `after` and Turnkey's cursor must be honoured.
func TestHTTPClient_WalletWithTwoHundredFiftyAccountsPages(t *testing.T) {
	stubAfters, stubIgnoreAfter = nil, false
	idx := make([]int, 250)
	for i := range idx {
		idx[i] = i
	}
	f := newFakeTurnkey(t, idx...)
	srv := turnkeyHTTPStub(t, f, "ACTIVITY_STATUS_COMPLETED")
	keyPath, _ := writeAPIKey(t)
	tf := &turnkeyFlags{Org: "o", Wallet: "w", AdminAPIKey: keyPath, BaseURL: srv.URL}

	sg, err := tf.newSigner(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"m/44'/60'/0'/0/250"}, f.created, "index 250, not 10 or 100")
	assert.Equal(t, f.didKeyAt(t, "m/44'/60'/0'/0/250"), sg.DIDKey())
	// One listing, with two cursors: after account 99, then after account 199.
	// The new account is read by the address the create returned.
	assert.Equal(t, []string{f.accounts[99].ID, f.accounts[199].ID}, stubAfters)
	assert.Equal(t, 1, f.lists)
	assert.Equal(t, []string{f.accounts[250].Address}, f.gotAddrs)

	// An account on the third page is found by address.
	want := f.didKeyAt(t, "m/44'/60'/0'/0/230")
	got, err := tf.existingSigner(context.Background(), want)
	require.NoError(t, err)
	assert.Equal(t, want, got.DIDKey())
	data := []byte(`{"n":1}`)
	sig, err := got.Sign(context.Background(), data)
	require.NoError(t, err)
	pub, _ := didkey.Decode(got.DIDKey())
	require.NoError(t, pub.Verify(data, sig))

	_, err = tf.existingSigner(context.Background(), newSecpDIDKey(t))
	require.Error(t, err)

	// The client itself returns every account.
	api, err := tf.client()
	require.NoError(t, err)
	all, err := api.ListWalletAccounts(context.Background(), "o", "w")
	require.NoError(t, err)
	assert.Len(t, all, 251)
}

// Turnkey ignoring `after` returns the same full page forever: stop.
func TestHTTPClient_StuckCursorStops(t *testing.T) {
	stubAfters, stubIgnoreAfter = nil, true
	t.Cleanup(func() { stubIgnoreAfter = false })
	idx := make([]int, 150)
	for i := range idx {
		idx[i] = i
	}
	f := newFakeTurnkey(t, idx...)
	srv := turnkeyHTTPStub(t, f, "ACTIVITY_STATUS_COMPLETED")
	keyPath, _ := writeAPIKey(t)
	tf := &turnkeyFlags{Org: "o", Wallet: "w", AdminAPIKey: keyPath, BaseURL: srv.URL}
	api, err := tf.client()
	require.NoError(t, err)
	_, err = api.ListWalletAccounts(context.Background(), "o", "w")
	require.Error(t, err)
	assert.Equal(t, "turnkey: wallet account paging did not advance", err.Error())
	assert.LessOrEqual(t, len(stubAfters), 3, "it stops at once, not after a thousand pages")
}

func newSecpDIDKey(t *testing.T) string {
	t.Helper()
	k, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	return didkey.FromSecp256k1(k.PubKey()).DIDKey()
}

func TestEthAddress_KnownVector(t *testing.T) {
	// The address of private key 1.
	var one secp256k1.ModNScalar
	one.SetInt(1)
	k := secp256k1.NewPrivateKey(&one)
	assert.Equal(t, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", ethAddress(k.PubKey()))
}

// --- the onboarding credential only ever signs car DIDs ---

// countingServer answers 404 to everything and counts the requests.
func countingServer(t *testing.T) (url string, calls *atomic.Int64) {
	t.Helper()
	calls = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, calls
}

// opDirectory serves didStr whose latest operation is current, and records
// what is submitted.
func opDirectory(t *testing.T, didStr string, current did.Operation) (url string, ops *[]*did.Operation) {
	t.Helper()
	var mu sync.Mutex
	ops = &[]*did.Operation{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/log/audit"):
			_ = json.NewEncoder(w).Encode([]map[string]any{{"cid": "bafyprev", "operation": current}})
		case r.Method == http.MethodPost:
			var op did.Operation
			require.NoError(t, json.NewDecoder(r.Body).Decode(&op))
			mu.Lock()
			*ops = append(*ops, &op)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"did":"` + didStr + `","cid":"bafynew"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, ops
}

const errCarsOnly = "the onboarding credential can only sign car DIDs"

func onboardingArgs(t *testing.T, baseURL string) []string {
	t.Helper()
	keyPath, _ := writeAPIKey(t)
	return []string{"--turnkey-org", "o", "--turnkey-wallet", "w", "--turnkey-api-key", keyPath, "--turnkey-base-url", baseURL}
}

func TestCreate_OnboardingCredentialOnlyCreatesCars(t *testing.T) {
	tkURL, calls := countingServer(t)
	dirURL, ops := opDirectory(t, "did:dimo:x", did.Operation{})
	tk := onboardingArgs(t, tkURL)
	for _, args := range [][]string{
		{"create", "--org"},
		{"create", "--org-host", "https://h.example"},
		{"create", "--alias", "person.example"},
	} {
		args = append(append(args, tk...), "--server", dirURL)
		stderr, code := runDimocli(t, args...)
		assert.Equal(t, 1, code, args[1])
		assert.Contains(t, stderr, errCarsOnly, args[1])
	}
	assert.Zero(t, calls.Load(), "refused before any Turnkey call")
	assert.Empty(t, *ops)
}

// orgOp is an org DID's operation: no control commitment, a #signing key.
func orgOp(rotationKey string) did.Operation {
	return did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{rotationKey},
		VerificationMethods: map[string]string{"signing": rotationKey}}
}

// carOp is a car DID's operation: controlled, no verification methods.
func carOp(t *testing.T, rotationKey string) did.Operation {
	t.Helper()
	_, commitment, err := newCommitment("did:dimo:fleet", 0)
	require.NoError(t, err)
	return did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{rotationKey}, ControlCommitment: &commitment}
}

func TestRotateAndUpdate_OnboardingCredentialRefusesNonCarDIDs(t *testing.T) {
	tkURL, calls := countingServer(t)
	dirURL, ops := opDirectory(t, "did:dimo:org", orgOp(newSecpDIDKey(t)))
	tk := onboardingArgs(t, tkURL)
	for _, args := range [][]string{
		{"rotate", "--did", "did:dimo:org"},
		{"rotate", "--did", "did:dimo:org", "--to-turnkey"},
		{"update", "--did", "did:dimo:org", "--alias", "at://org.example"},
	} {
		args = append(append(args, tk...), "--server", dirURL)
		stderr, code := runDimocli(t, args...)
		assert.Equal(t, 1, code, strings.Join(args[:3], " "))
		assert.Contains(t, stderr, errCarsOnly, strings.Join(args[:3], " "))
	}
	assert.Zero(t, calls.Load(), "refused before any Turnkey call")
	assert.Empty(t, *ops)
}

func TestRotateAndUpdate_OnboardingCredentialSignsCarDIDs(t *testing.T) {
	for _, cmd := range [][]string{
		{"rotate", "--did", "did:dimo:car"},
		{"update", "--did", "did:dimo:car", "--alias", "vin-1.example"},
	} {
		f := newFakeTurnkey(t, 0)
		srv := turnkeyHTTPStub(t, f, "ACTIVITY_STATUS_COMPLETED")
		old := f.didKeyAt(t, "m/44'/60'/0'/0/0")
		dirURL, ops := opDirectory(t, "did:dimo:car", carOp(t, old))
		args := append(append(cmd, onboardingArgs(t, srv.URL)...), "--server", dirURL)
		stderr, code := runDimocli(t, args...)
		require.Equal(t, 0, code, stderr)
		require.Len(t, *ops, 1, cmd[0])
		verifyOp(t, old, (*ops)[0])
	}
}

// --- onboarding cost: one listing per car, none with --turnkey-index ---

func TestTurnkeyFlags_OneListingPerCarAndTheReturnedAddressIsUsed(t *testing.T) {
	f := newFakeTurnkey(t, 0)
	tf := tkFlags(f, true)
	for i := 1; i <= 3; i++ {
		sg, err := tf.newSigner(context.Background())
		require.NoError(t, err)
		path := fmt.Sprintf("m/44'/60'/0'/0/%d", i)
		assert.Equal(t, f.didKeyAt(t, path), sg.DIDKey())
		assert.Equal(t, i, f.lists, "one listing per car, not two")
		created := f.accounts[len(f.accounts)-1]
		assert.Equal(t, created.Address, f.gotAddrs[len(f.gotAddrs)-1], "the key is read by the address the create returned")
		assert.Equal(t, created.Address, sg.signWith)
	}
	assert.Len(t, f.gotAddrs, 3, "one lookup per car")
}

func TestTurnkeyFlags_IndexCreatesAtThatPathWithoutListing(t *testing.T) {
	f := newFakeTurnkey(t, 0, 1, 2)
	tf := tkFlags(f, true)
	idx := uint32(41)
	tf.Index = &idx
	sg, err := tf.newSigner(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"m/44'/60'/0'/0/41"}, f.created)
	assert.Equal(t, f.didKeyAt(t, "m/44'/60'/0'/0/41"), sg.DIDKey())
	assert.Zero(t, f.lists, "no listing with --turnkey-index")
}

func TestTurnkeyFlags_IndexThatExistsIsReported(t *testing.T) {
	f := newFakeTurnkey(t, 0, 1, 2)
	tf := tkFlags(f, true)
	idx := uint32(2)
	tf.Index = &idx
	_, err := tf.newSigner(context.Background())
	require.Error(t, err)
	assert.Equal(t, "account index 2 already exists", err.Error())
	assert.Empty(t, f.created)
	assert.Zero(t, f.lists)
}

func TestTurnkeyFlags_IndexNeedsTurnkey(t *testing.T) {
	idx := uint32(1)
	assert.EqualError(t, (&turnkeyFlags{Index: &idx}).validate(), "--turnkey-index needs --turnkey-org, --turnkey-wallet and a Turnkey credential")
}

func TestCreate_TurnkeyIndexFlag(t *testing.T) {
	f := newFakeTurnkey(t, 0)
	srv := turnkeyHTTPStub(t, f, "ACTIVITY_STATUS_COMPLETED")
	dirURL, ops := opDirectory(t, "did:dimo:new", did.Operation{})
	base := append([]string{"create", "--controller", "did:dimo:avis", "--server", dirURL}, onboardingArgs(t, srv.URL)...)

	stderr, code := runDimocli(t, append(base, "--turnkey-index", "7")...)
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, []string{"m/44'/60'/0'/0/7"}, f.created)
	assert.Zero(t, f.lists)
	require.Len(t, *ops, 1)
	assert.Equal(t, []string{f.didKeyAt(t, "m/44'/60'/0'/0/7")}, (*ops)[0].RotationKeys)

	stderr, code = runDimocli(t, append(base, "--turnkey-index", "7")...)
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "account index 7 already exists")
	assert.Len(t, *ops, 1)

	for _, bad := range []string{"-1", "2147483648", "x"} {
		_, code = runDimocli(t, append(base, "--turnkey-index", bad)...)
		assert.NotEqual(t, 0, code, bad)
	}
}
