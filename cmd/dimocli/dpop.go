package main

import (
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
	priv, err := LoadKey(did)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	proof, err := dpopProof(priv, strings.ToUpper(*method), *url, *token, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(proof)
}
