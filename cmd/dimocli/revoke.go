package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

func runRevokeAll(args []string) {
	fs := flag.NewFlagSet("revoke-all", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "DID to bump SACD epoch for (required)")
	fs.Parse(args)

	if *didStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --did is required\n")
		os.Exit(1)
	}

	// Load private key.
	privKey, err := LoadKey(*didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	ctx := context.Background()

	// Resolve to get current sacdEpoch.
	doc, err := c.Resolve(ctx, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving DID: %v\n", err)
		os.Exit(1)
	}

	newEpoch := doc.DimoSacdEpoch + 1

	// Get the latest CID and operation.
	prevCID, currentOp, err := getLatestCIDAndOp(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest state: %v\n", err)
		os.Exit(1)
	}

	// Build update operation with bumped sacdEpoch.
	unsignedOp := &did.UnsignedOperation{
		Type:                did.OpTypeCreate,
		RotationKeys:        currentOp.RotationKeys,
		VerificationMethods: currentOp.VerificationMethods,
		AlsoKnownAs:         currentOp.AlsoKnownAs,
		Services:            currentOp.Services,
		SacdEpoch:           &newEpoch,
		Prev:                &prevCID,
	}

	// Sign.
	data, err := json.Marshal(unsignedOp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling operation: %v\n", err)
		os.Exit(1)
	}

	sig, err := dimocrypto.SignOperation(privKey, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing operation: %v\n", err)
		os.Exit(1)
	}

	op := &did.Operation{
		Type:                unsignedOp.Type,
		RotationKeys:        unsignedOp.RotationKeys,
		VerificationMethods: unsignedOp.VerificationMethods,
		AlsoKnownAs:         unsignedOp.AlsoKnownAs,
		Services:            unsignedOp.Services,
		SacdEpoch:           unsignedOp.SacdEpoch,
		Prev:                unsignedOp.Prev,
		Sig:                 sig,
	}

	resp, err := c.Submit(ctx, *didStr, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting epoch bump: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("SACD epoch bumped for: %s\n", resp.DID)
	fmt.Printf("New epoch: %d\n", newEpoch)
	fmt.Printf("CID: %s\n", resp.CID)
}
