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
	"github.com/DIMO-Network/did-directory/pkg/control"
	"github.com/DIMO-Network/did-directory/pkg/sacd"
)

func runSACDGrant(args []string) {
	fs := flag.NewFlagSet("sacd-grant", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	grantor := fs.String("grantor", "", "grantor DID: the asset's controller of record, or the asset itself if uncontrolled (required)")
	grantee := fs.String("grantee", "", "grantee DID (required)")
	asset := fs.String("asset", "", "asset DID being shared (required)")
	permissions := fs.String("permissions", "telemetry:read", "permissions (comma-separated)")
	expires := fs.String("expires", "", "expiration time (RFC3339, default: 24h from now)")
	out := fs.String("out", "", "output file (default: stdout)")
	fs.Parse(args)

	if *grantor == "" || *grantee == "" || *asset == "" {
		fmt.Fprintf(os.Stderr, "Error: --grantor, --grantee and --asset are required\n")
		os.Exit(1)
	}

	// Load grantor's key. A controlled asset has no signing key of its own.
	privKey, err := LoadKey(*grantor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading grantor key: %v\n", err)
		os.Exit(1)
	}

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	state, err := c.Control(context.Background(), *asset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving asset control state: %v\n", err)
		os.Exit(1)
	}

	var era uint64
	var proof *control.Opening
	if cur := state.Current(); cur != nil {
		opening, err := LoadOpening(*asset)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s is a controlled asset and no control opening is available: %v\n", *asset, err)
			os.Exit(1)
		}
		if opening.Controller != *grantor || opening.Era != cur.Number {
			fmt.Fprintf(os.Stderr, "Error: %s is not the controller of record for %s in era %d\n", *grantor, *asset, cur.Number)
			os.Exit(1)
		}
		era = cur.Number
		proof = opening
	} else if *asset != *grantor {
		fmt.Fprintf(os.Stderr, "Error: %s is not a controlled DID; only it can grant access to itself\n", *asset)
		os.Exit(1)
	}

	// Set expiration.
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	if *expires != "" {
		expiresAt = *expires
	}

	sacdDoc := &sacd.Document{
		Type:         sacd.DocumentType,
		Grantor:      *grantor,
		Grantee:      *grantee,
		Asset:        *asset,
		Era:          era,
		Permissions:  strings.Split(*permissions, ","),
		EffectiveAt:  time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    expiresAt,
		ControlProof: proof,
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
