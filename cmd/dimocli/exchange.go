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
	grant := fs.String("grant", "", "at:// URI of the delegation to exercise; omit to act as the vehicle's controller")
	vehicle := fs.String("vehicle", "", "vehicle DID")
	abilities := fs.String("abilities", "", "abilities to request (comma-separated)")
	audience := fs.String("audience", "", "audience to request (comma-separated; dauth's default otherwise)")
	client := fs.String("client", "", "app DID to attest as client_assertion (its key must be in the keystore)")
	claims := fs.Bool("claims", false, "print the token's decoded claims instead of the token")
	_ = fs.Parse(args)

	if *didFlag == "" || *vehicle == "" || *abilities == "" {
		fmt.Fprintln(os.Stderr, "Error: --did, --vehicle and --abilities are required")
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
	// Client is an app DID whose key is in the keystore; it attests the
	// request with a client assertion signed by that key.
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

	exchangeURL := base + "/exchange"

	// The identity token is addressed to the exchange, which refuses one
	// addressed anywhere else.
	identity, _, err := signIn(base, req.Caller, priv, "signing", []string{exchangeURL})
	if err != nil {
		return nil, fmt.Errorf("sign in as %s: %w", req.Caller, err)
	}

	body := map[string]any{"vehicle": req.Vehicle, "abilities": req.Abilities}
	if req.Grant != "" {
		body["grant"] = req.Grant
	}
	if len(req.Audience) > 0 {
		body["audience"] = req.Audience
	}
	if req.Client != "" {
		appKey, err := LoadKey(req.Client)
		if err != nil {
			return nil, err
		}
		assertion, err := clientAssertion(appKey, req.Client, exchangeURL, &priv.PublicKey, time.Now())
		if err != nil {
			return nil, fmt.Errorf("client assertion for %s: %w", req.Client, err)
		}
		body["client_assertion"] = assertion
	}

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
	jwk, err := publicJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := map[string]any{"jti": jti, "htm": method, "htu": url, "iat": now.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return signES256(key, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}, claims)
}

// clientAssertion is what dauth's exchange takes as client_assertion: a JWT
// the app signs with its #signing key, addressed to the exchange, good for two
// minutes, and bound to the caller's DPoP key by that key's thumbprint, so it
// attests this caller's request and no other.
func clientAssertion(appKey *ecdsa.PrivateKey, app, exchangeURL string, dpopKey *ecdsa.PublicKey, now time.Time) (string, error) {
	jwk, err := publicJWK(dpopKey)
	if err != nil {
		return "", err
	}
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": app, "sub": app, "aud": exchangeURL, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": jti, "cnf": map[string]string{"jkt": jwkThumbprint(jwk)},
	}
	return signES256(appKey, map[string]any{"alg": "ES256", "kid": app + "#signing"}, claims)
}

// publicJWK is a P-256 public key as a JWK.
func publicJWK(pub *ecdsa.PublicKey) (map[string]string, error) {
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("ES256 needs a P-256 key")
	}
	raw, err := pub.Bytes() // 0x04 || x || y
	if err != nil {
		return nil, err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return map[string]string{"kty": "EC", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:65])}, nil
}

// jwkThumbprint is the RFC 7638 thumbprint of an EC JWK: SHA-256 over the
// required members in lexicographic order, which is what cnf.jkt holds.
func jwkThumbprint(jwk map[string]string) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newJTI() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	return hex.EncodeToString(jti), nil
}

// signES256 assembles a compact JWS. The signature is the JWS form of ECDSA,
// r||s over SHA-256, which is the encoding SignOperation already produces.
func signES256(key *ecdsa.PrivateKey, header, claims map[string]any) (string, error) {
	if key.Curve != elliptic.P256() {
		return "", errors.New("ES256 needs a P-256 key")
	}
	b64 := base64.RawURLEncoding.EncodeToString
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
