package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/DIMO-Network/did-directory/pkg/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const orgDID = "did:dimo:avis"

// orgDirectory serves an org whose root and #signing are rootKey.
func orgDirectory(t *testing.T, rootKey string) *client.Client {
	t.Helper()
	current := did.Operation{Type: did.OpTypeCreate, RotationKeys: []string{rootKey}, VerificationMethods: map[string]string{"signing": rootKey}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/log/audit") {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"cid": "bafy", "operation": current}})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return client.New(srv.URL)
}

// fakeDauth issues dauth's sign-in text, checks the challenge signature
// against pub and the DPoP proof, and answers a token bound to the challenge's key.
func fakeDauth(t *testing.T, pub *didkey.PublicKey) string {
	t.Helper()
	var jkt, text string
	verifier := dpop.NewVerifier()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/signin/challenge":
			var req struct{ DID, Scope, JKT string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			jkt = req.JKT
			text = fmt.Sprintf("dauth.test wants you to sign in as\n%s\n\nFor: https://accounts.test\nScope: %s\nKey: %s\n\nNonce: n1\nIssued At: 2026-11-22T00:00:00Z\nExpiration Time: 2026-11-22T00:05:00Z", req.DID, req.Scope, req.JKT)
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": text, "nonce": "n1"})
		case "/signin/token":
			var body struct{ Nonce, Signature string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			got, err := verifier.Verify(r.Header.Get(dpop.HeaderName), http.MethodPost, srv.URL+"/signin/token", "")
			if err != nil || got != jkt || pub.Verify([]byte(text), body.Signature) != nil {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusUnauthorized)
				return
			}
			claims, _ := json.Marshal(map[string]any{"sub": orgDID, "cnf": map[string]string{"jkt": jkt}})
			tok := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
			_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "token_type": "DPoP", "expires_in": 600})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSignin_TurnkeyRootedOrgSignsInAndProvesTheTokenKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeTurnkey(t, 0)
	root := f.didKeyAt(t, "m/44'/60'/0'/0/0")
	pub, err := didkey.Decode(root)
	require.NoError(t, err)
	dauth := fakeDauth(t, pub)

	_, err = LoadKey(orgDID)
	require.Error(t, err, "the org has no local key")

	token, _, err := executeSignin(context.Background(), dauth, orgDID, "signing", nil, "read",
		tkFlags(f, false), orgDirectory(t, root))
	require.NoError(t, err)
	assert.Equal(t, 1, f.signed, "the challenge was signed through Turnkey")

	proof, err := makeDPoPProof(orgDID, token, "GET", "https://org.test/x", time.Now())
	require.NoError(t, err)
	claims, err := jwtClaims(token)
	require.NoError(t, err)
	var c struct{ Cnf struct{ Jkt string } }
	require.NoError(t, json.Unmarshal(claims, &c))
	jkt, err := dpop.NewVerifier().Verify(proof, "GET", "https://org.test/x", token)
	require.NoError(t, err)
	assert.Equal(t, c.Cnf.Jkt, jkt, "the proof's key is the one the token is bound to")
}

func TestSignin_FileKeyPathUnchanged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sg, err := newFileSignerNew()
	require.NoError(t, err)
	require.NoError(t, SaveKey(orgDID, sg.key))
	pub, _ := didkey.Decode(sg.DIDKey())
	dauth := fakeDauth(t, pub)
	token, _, err := executeSignin(context.Background(), dauth, orgDID, "signing", nil, "read", &turnkeyFlags{}, nil)
	require.NoError(t, err)
	proof, err := makeDPoPProof(orgDID, token, "GET", "https://org.test/x", time.Now())
	require.NoError(t, err)
	_, err = dpop.NewVerifier().Verify(proof, "GET", "https://org.test/x", token)
	require.NoError(t, err)
}

func TestSignin_RefusesTheOnboardingCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeTurnkey(t, 0)
	root := f.didKeyAt(t, "m/44'/60'/0'/0/0")
	_, _, err := executeSignin(context.Background(), "http://127.0.0.1:1", orgDID, "signing", nil, "read",
		tkFlags(f, true), orgDirectory(t, root))
	require.Error(t, err)
	assert.Equal(t, "the onboarding credential can't sign in as an org", err.Error())
	assert.Equal(t, 0, f.signed)
}
