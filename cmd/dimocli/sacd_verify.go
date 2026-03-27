package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
)

func runSACDVerify(args []string) {
	fs := flag.NewFlagSet("sacd-verify", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	file := fs.String("file", "", "SACD JSON file to verify (required)")
	fs.Parse(args)

	if *file == "" {
		fmt.Fprintf(os.Stderr, "Error: --file is required\n")
		os.Exit(1)
	}

	// Read SACD file.
	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	var sacdDoc sacd.Document
	if err := json.Unmarshal(data, &sacdDoc); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SACD: %v\n", err)
		os.Exit(1)
	}

	// Resolve grantor DID.
	c := client.New(*server)
	doc, err := c.Resolve(context.Background(), sacdDoc.Grantor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving grantor DID: %v\n", err)
		os.Exit(1)
	}

	// Extract grantor's verification key from DID document.
	if len(doc.VerificationMethod) == 0 {
		fmt.Fprintf(os.Stderr, "Error: grantor DID has no verification methods\n")
		os.Exit(1)
	}

	// Use the first verification method's key.
	grantorDIDKey := "did:key:" + doc.VerificationMethod[0].PublicKeyMultibase

	// Verify the SACD.
	if err := sacdDoc.Verify(grantorDIDKey, doc.DimoSacdEpoch); err != nil {
		fmt.Printf("SACD INVALID: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("SACD VALID")
	fmt.Printf("  Grantor: %s\n", sacdDoc.Grantor)
	fmt.Printf("  Grantee: %s\n", sacdDoc.Grantee)
	fmt.Printf("  Asset: %s\n", sacdDoc.Asset)
	fmt.Printf("  Permissions: %v\n", sacdDoc.Permissions)
	fmt.Printf("  Epoch: %d\n", sacdDoc.SacdEpoch)
	fmt.Printf("  Effective: %s\n", sacdDoc.EffectiveAt)
	fmt.Printf("  Expires: %s\n", sacdDoc.ExpiresAt)
}
