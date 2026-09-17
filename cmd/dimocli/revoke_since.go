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

// runRevokeSince records a compromise window for a controlled DID, ends the
// current era and rotates its custody key in the same operation. Control stays
// with the same controller: the new era's commitment opens to the same DID.
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

	cur, err := currentEra(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// The revocation ends the era, so control has to be re-committed. The
	// controller does not change: only the era number and the salt do.
	oldOpening, err := LoadOpening(*didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: no control opening available for %s: %v\n", *didStr, err)
		os.Exit(1)
	}

	newCustody, newCustodyDIDKey, err := newKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	nextEra := cur.Number + 1
	newOpening, commitment, err := newCommitment(oldOpening.Controller, nextEra)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating control commitment: %v\n", err)
		os.Exit(1)
	}
	issued := time.Now().UTC().Format(time.RFC3339)

	op, err := signOp(custodyKey, &did.UnsignedOperation{
		Type:                did.OpTypeRevokeSince,
		RotationKeys:        []string{newCustodyDIDKey},
		VerificationMethods: currentOp.VerificationMethods,
		AlsoKnownAs:         currentOp.AlsoKnownAs,
		Services:            currentOp.Services,
		ControlCommitment:   &commitment,
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
	if err := SaveOpening(*didStr, newOpening); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save control opening: %v\n", err)
	}

	fmt.Printf("Revocation window recorded: %s\n", resp.DID)
	fmt.Printf("Compromise window: [%s, %s]\n", *since, issued)
	fmt.Printf("New era: %d (starts %s) — every SACD from era %d is now invalid\n", nextEra, issued, cur.Number)
	fmt.Printf("Custody key rotated. CID: %s\n", resp.CID)
}
