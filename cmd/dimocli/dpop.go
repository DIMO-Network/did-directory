package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// runDPoP prints a DPoP proof that presents an identity token signin printed,
// for one request, so a script calling the org host with curl can send the
// token under the DPoP scheme. The key is the keystore's key for the token's
// sub, which is the key signin bound the token to.
func runDPoP(args []string) {
	fs := flag.NewFlagSet("dpop", flag.ExitOnError)
	token := fs.String("token", "", "identity token the request presents")
	method := fs.String("method", "GET", "the request's HTTP method")
	url := fs.String("url", "", "the request's URL")
	didFlag := fs.String("did", "", "DID whose key signs (default: the token's sub)")
	fs.Parse(args)

	if *token == "" || *url == "" {
		fmt.Fprintln(os.Stderr, "Error: --token and --url are required")
		os.Exit(1)
	}
	did := *didFlag
	if did == "" {
		raw, err := jwtClaims(*token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		var claims struct {
			Sub string `json:"sub"`
		}
		if err := json.Unmarshal(raw, &claims); err != nil || claims.Sub == "" {
			fmt.Fprintln(os.Stderr, "Error: the token names no sub; pass --did")
			os.Exit(1)
		}
		did = claims.Sub
	}
	proof, err := makeDPoPProof(did, *token, strings.ToUpper(*method), *url, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(proof)
}

// makeDPoPProof signs a proof for one request presenting token, with the key
// signin bound the token to: the DID's keystore key, or for a Turnkey-rooted
// DID the P-256 key signin stored beside it (<did>.dpop.json). When both exist,
// the one whose thumbprint is the token's cnf.jkt wins.
func makeDPoPProof(did, token, method, url string, now time.Time) (string, error) {
	var keys []*ecdsa.PrivateKey
	var firstErr error
	for _, load := range []func(string) (*ecdsa.PrivateKey, error){LoadKey, LoadDPoPKey} {
		k, err := load(did)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return "", firstErr
	}
	priv := keys[0]
	if raw, err := jwtClaims(token); err == nil {
		var c struct {
			Cnf struct {
				Jkt string `json:"jkt"`
			} `json:"cnf"`
		}
		if json.Unmarshal(raw, &c) == nil && c.Cnf.Jkt != "" {
			for _, k := range keys {
				if jwk, err := publicJWK(&k.PublicKey); err == nil && jwkThumbprint(jwk) == c.Cnf.Jkt {
					priv = k
					break
				}
			}
		}
	}
	return dpopProof(priv, method, url, token, now)
}
