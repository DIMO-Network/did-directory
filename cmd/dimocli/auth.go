package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
)

func runAuth(args []string) {
	fs := flag.NewFlagSet("auth", flag.ExitOnError)
	authURL := fs.String("auth-url", defaultAuthServer(), "auth service URL")
	didStr := fs.String("did", "", "developer DID (required)")
	sacdFile := fs.String("sacd", "", "path to SACD JSON file (required)")
	audience := fs.String("audience", "my-app", "audience for the JWT (comma-separated)")
	fs.Parse(args)

	if *didStr == "" || *sacdFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --did and --sacd are required\n")
		os.Exit(1)
	}

	// Use the client for verbose HTTP logging.
	c := client.New(*authURL)
	c.SetVerbose(isVerbose())
	ctx := context.Background()

	// Load developer's key.
	privKey, err := LoadKey(*didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}

	// Step 1: Get challenge from auth service.
	challengeRespBody, err := c.RawGet(ctx, *authURL+"/v1/challenge")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting challenge: %v\n", err)
		os.Exit(1)
	}

	var challengeBody struct {
		Challenge string `json:"challenge"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(challengeRespBody, &challengeBody); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing challenge: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Sign the challenge.
	challengeBytes, err := base64.RawURLEncoding.DecodeString(challengeBody.Challenge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding challenge: %v\n", err)
		os.Exit(1)
	}

	sig, err := dimocrypto.SignOperation(privKey, challengeBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing challenge: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Read SACD file.
	sacdData, err := os.ReadFile(*sacdFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading SACD file: %v\n", err)
		os.Exit(1)
	}

	var sacdDoc sacd.Document
	if err := json.Unmarshal(sacdData, &sacdDoc); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SACD: %v\n", err)
		os.Exit(1)
	}

	// Step 4: POST to auth service.
	authReq := struct {
		DID       string          `json:"did"`
		Challenge string          `json:"challenge"`
		Signature string          `json:"signature"`
		SACDs     []sacd.Document `json:"sacds"`
		Audience  []string        `json:"audience"`
	}{
		DID:       *didStr,
		Challenge: challengeBody.Challenge,
		Signature: sig,
		SACDs:     []sacd.Document{sacdDoc},
		Audience:  strings.Split(*audience, ","),
	}

	reqBody, err := json.Marshal(authReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling auth request: %v\n", err)
		os.Exit(1)
	}

	status, respBody, err := c.RawPost(ctx, *authURL+"/v1/auth", reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error authenticating: %v\n", err)
		os.Exit(1)
	}

	if status != 200 {
		fmt.Fprintf(os.Stderr, "Auth failed (status %d): %s\n", status, string(respBody))
		os.Exit(1)
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing token response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("JWT Token:\n%s\n\n", tokenResp.Token)

	// Decode and print claims.
	parts := strings.Split(tokenResp.Token, ".")
	if len(parts) == 3 {
		claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			var claims map[string]any
			if err := json.Unmarshal(claimsJSON, &claims); err == nil {
				pretty, _ := json.MarshalIndent(claims, "", "  ")
				fmt.Printf("Claims:\n%s\n", string(pretty))
			}
		}
	}
}
