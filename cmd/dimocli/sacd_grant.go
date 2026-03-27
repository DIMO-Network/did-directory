package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
)

func runSACDGrant(args []string) {
	fs := flag.NewFlagSet("sacd-grant", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	grantor := fs.String("grantor", "", "grantor DID (required)")
	grantee := fs.String("grantee", "", "grantee DID (required)")
	permissions := fs.String("permissions", "telemetry:read", "permissions (comma-separated)")
	expires := fs.String("expires", "", "expiration time (RFC3339, default: 24h from now)")
	out := fs.String("out", "", "output file (default: stdout)")
	fs.Parse(args)

	if *grantor == "" || *grantee == "" {
		fmt.Fprintf(os.Stderr, "Error: --grantor and --grantee are required\n")
		os.Exit(1)
	}

	// Load grantor's key.
	privKey, err := LoadKey(*grantor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading grantor key: %v\n", err)
		os.Exit(1)
	}

	// Resolve grantor DID to get current sacdEpoch.
	c := client.New(*server)
	c.SetVerbose(isVerbose())
	doc, err := c.Resolve(context.Background(), *grantor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving grantor DID: %v\n", err)
		os.Exit(1)
	}

	// Set expiration.
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if *expires != "" {
		expiresAt = *expires
	}

	// Build SACD document.
	sacdDoc := &sacd.Document{
		Type:        "dimo.sacd.v2",
		Grantor:     *grantor,
		Grantee:     *grantee,
		Asset:       *grantor,
		SacdEpoch:   doc.DimoSacdEpoch,
		Permissions: strings.Split(*permissions, ","),
		EffectiveAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:   expiresAt,
		Signature:   "",
	}

	// Sign the SACD data (everything except signature field).
	payload, err := sacdDoc.UnsignedPayload()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling SACD: %v\n", err)
		os.Exit(1)
	}

	sig, err := dimocrypto.SignOperation(privKey, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing SACD: %v\n", err)
		os.Exit(1)
	}
	sacdDoc.Signature = sig

	// Marshal final document.
	output, err := json.MarshalIndent(sacdDoc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling SACD document: %v\n", err)
		os.Exit(1)
	}

	if *out != "" {
		if err := os.WriteFile(*out, output, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "SACD written to %s\n", *out)
	} else {
		fmt.Println(string(output))
	}
}
