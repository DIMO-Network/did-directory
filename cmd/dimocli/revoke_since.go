package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

// runRevokeSince records a compromise window for a controlled DID's current era
// and rotates its custody key in the same operation.
func runRevokeSince(args []string) {
	fs := flag.NewFlagSet("revoke-since", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "controlled DID (required)")
	since := fs.String("since", "", "start of the compromise window (RFC3339, required)")
	fs.Parse(args)

	if *didStr == "" || *since == "" {
		fmt.Fprintf(os.Stderr, "Error: --did and --since are required\n")
		os.Exit(1)
	}
	if _, err := time.Parse(time.RFC3339, *since); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid --since: %v\n", err)
		os.Exit(1)
	}

	custodyKey, err := LoadKey(*didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading custody key: %v\n", err)
		os.Exit(1)
	}

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	ctx := context.Background()

	prevCID, currentOp, err := getLatestCIDAndOp(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest state: %v\n", err)
		os.Exit(1)
	}
	if !currentOp.IsControlled() {
		fmt.Fprintf(os.Stderr, "Error: %s is not a controlled DID\n", *didStr)
		os.Exit(1)
	}

	newCustody, newCustodyDIDKey, err := newKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	issued := time.Now().UTC().Format(time.RFC3339)

	op, err := signOp(custodyKey, &did.UnsignedOperation{
		Type:                did.OpTypeRevokeSince,
		RotationKeys:        []string{newCustodyDIDKey},
		VerificationMethods: currentOp.VerificationMethods,
		AlsoKnownAs:         currentOp.AlsoKnownAs,
		Services:            currentOp.Services,
		ControlCommitment:   currentOp.ControlCommitment,
		RevokeSince:         since,
		EffectiveAt:         &issued,
		Prev:                &prevCID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	resp, err := c.Submit(ctx, *didStr, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting revocation: %v\n", err)
		os.Exit(1)
	}

	if err := SaveKey(*didStr, newCustody); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save new custody key: %v\n", err)
	}

	fmt.Printf("Revocation window recorded: %s\n", resp.DID)
	fmt.Printf("Revoked: grants issued in [%s, %s]\n", *since, issued)
	fmt.Printf("Custody key rotated. CID: %s\n", resp.CID)
}
