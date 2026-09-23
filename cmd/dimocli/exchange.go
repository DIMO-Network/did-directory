package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
)

// runExchange asks dauth for an access token: it signs in as the caller,
// proves possession of the caller's key with an RFC 9449 DPoP proof, and
// exchanges the identity token for a token carrying the coverage the org host
// computed for one delegation over one vehicle (spec §11.1). The DPoP key is
// the caller's own #signing key, so the token is bound to what the keystore
// already holds; a resource server such as dq will want a proof from the same
// key on every request.
func runExchange(args []string) {
	fs := flag.NewFlagSet("exchange", flag.ExitOnError)
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL, as dauth publishes it (its PUBLIC_BASE_URL)")
	didFlag := fs.String("did", "", "caller DID (its key must be in the keystore)")
	grant := fs.String("grant", "", "at:// URI of the delegation to exercise")
	vehicle := fs.String("vehicle", "", "vehicle DID")
	abilities := fs.String("abilities", "", "abilities to request (comma-separated)")
	audience := fs.String("audience", "", "audience to request (comma-separated; dauth's default otherwise)")
	client := fs.String("client", "", "app DID to attest as client_assertion (its key must be in the keystore)")
	claims := fs.Bool("claims", false, "print the token's decoded claims instead of the token")
	_ = fs.Parse(args)

	if *didFlag == "" || *grant == "" || *vehicle == "" || *abilities == "" {
		fmt.Fprintln(os.Stderr, "Error: --did, --grant, --vehicle and --abilities are required")
		os.Exit(1)
	}
	req := exchangeRequest{Caller: *didFlag, Grant: *grant, Vehicle: *vehicle, Abilities: strings.Split(*abilities, ","), Client: *client}
	if *audience != "" {
		req.Audience = strings.Split(*audience, ",")
	}
	access, err := mintAccessToken(*dauth, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if isVerbose() {
		fmt.Fprintf(os.Stderr, "%s token for %s (expires in %ds)\n", access.TokenType, *didFlag, access.ExpiresIn)
	}
	if !*claims {
		fmt.Println(access.Token)
		return
	}
	payload, err := jwtClaims(access.Token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(payload))
}

// exchangeRequest is what a caller asks dauth for: one delegation, one
// vehicle, some abilities, optionally on behalf of an app.
type exchangeRequest struct {
	Caller    string
	Grant     string
	Vehicle   string
	Abilities []string
	Audience  []string
	// Client is an app DID whose key is in the keystore; it is attested with
	// its own identity token as client_assertion.
	Client string
}

// accessToken is dauth's answer, plus the key the token is bound to, which
// every request that presents the token must prove again.
type accessToken struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
	key       *ecdsa.PrivateKey
}

// mintAccessToken signs in as the caller, proves the caller's key with a DPoP
// proof for POST /exchange, and returns the access token dauth minted. The
// DPoP key is the caller's #signing key from the keystore.
func mintAccessToken(dauth string, req exchangeRequest) (*accessToken, error) {
	priv, err := LoadKey(req.Caller)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(dauth, "/")

	identity, _, err := signIn(base, req.Caller, priv, "signing", nil)
	if err != nil {
		return nil, fmt.Errorf("sign in as %s: %w", req.Caller, err)
	}

	body := map[string]any{"grant": req.Grant, "vehicle": req.Vehicle, "abilities": req.Abilities}
	if len(req.Audience) > 0 {
		body["audience"] = req.Audience
	}
	if req.Client != "" {
		appKey, err := LoadKey(req.Client)
		if err != nil {
			return nil, err
		}
		assertion, _, err := signIn(base, req.Client, appKey, "signing", nil)
		if err != nil {
			return nil, fmt.Errorf("sign in as app %s: %w", req.Client, err)
		}
		body["client_assertion"] = assertion
	}

	exchangeURL := base + "/exchange"
	proof, err := dpopProof(priv, "POST", exchangeURL, "", time.Now())
	if err != nil {
		return nil, fmt.Errorf("DPoP proof: %w", err)
	}
	out := &accessToken{key: priv}
	headers := map[string]string{"Authorization": "Bearer " + identity, "DPoP": proof}
	if err := sendJSON("POST", exchangeURL, headers, body, out); err != nil {
		return nil, fmt.Errorf("POST /exchange: %w", err)
	}
	return out, nil
}

// dpopProof signs an RFC 9449 proof JWT for a request with the given method
// and URL: ES256, typ dpop+jwt, the public key in the header as a JWK, and
// jti, htm, htu and iat as claims, plus ath, the hash of accessToken, when the
// request presents one. The signature is the JWS form of ECDSA, r||s over
// SHA-256, which is the encoding SignOperation already produces.
func dpopProof(key *ecdsa.PrivateKey, method, url, accessToken string, now time.Time) (string, error) {
	if key.Curve != elliptic.P256() {
		return "", errors.New("DPoP proofs need a P-256 key")
	}
	b64 := base64.RawURLEncoding.EncodeToString
	size := (key.Curve.Params().BitSize + 7) / 8
	header := map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": b64(key.X.FillBytes(make([]byte, size))),
			"y": b64(key.Y.FillBytes(make([]byte, size))),
		},
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{"jti": hex.EncodeToString(jti), "htm": method, "htu": url, "iat": now.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = b64(sum[:])
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(h) + "." + b64(c)
	sig, err := dimocrypto.SignOperation(key, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + sig, nil
}

// jwtClaims returns a JWT's payload, re-indented, without verifying it: the
// caller just minted it and wants to read it.
func jwtClaims(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	return json.MarshalIndent(claims, "", "  ")
}
