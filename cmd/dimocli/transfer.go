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

// runTransfer moves a controlled DID to a new controller of record and starts a
// new control era. The CLI plays both sides: it signs with the current custody
// key and generates the new controller's custody key and opening.
func runTransfer(args []string) {
	fs := flag.NewFlagSet("transfer", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "controlled DID to transfer (required)")
	to := fs.String("to", "", "new controller of record DID (required)")
	tk := bindTurnkeyFlags(fs)
	fs.Parse(args)

	if err := tk.validate(); err != nil {
		fatal(err)
	}
	if err := tk.refuseSensitive(); err != nil {
		fatal(err)
	}
	if *didStr == "" || *to == "" {
		fmt.Fprintf(os.Stderr, "Error: --did and --to are required\n")
		os.Exit(1)
	}
	if !did.IsValidDID(*to) {
		fmt.Fprintf(os.Stderr, "Invalid --to: %s\n", *to)
		os.Exit(1)
	}

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	ctx := context.Background()

	cur, err := currentEra(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	prevCID, currentOp, err := getLatestCIDAndOp(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest state: %v\n", err)
		os.Exit(1)
	}

	custodySigner, err := resolveSigner(ctx, tk, *didStr, currentOp, purposeTransfer)
	if err != nil {
		fatal(err)
	}
	newCustodyDIDKey, saveCustody, err := newCustody(ctx, tk)
	if err != nil {
		fatal(err)
	}
	nextEra := cur.Number + 1
	opening, commitment, err := newCommitment(*to, nextEra)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating control commitment: %v\n", err)
		os.Exit(1)
	}
	effectiveAt := time.Now().UTC().Format(time.RFC3339)

	op, err := signOpWith(ctx, custodySigner, &did.UnsignedOperation{
		Type:              did.OpTypeTransfer,
		RotationKeys:      []string{newCustodyDIDKey},
		AlsoKnownAs:       currentOp.AlsoKnownAs,
		Services:          currentOp.Services,
		ControlCommitment: &commitment,
		EffectiveAt:       &effectiveAt,
		Prev:              &prevCID,
	})
	if err != nil {
		fatal(err)
	}

	resp, err := c.Submit(ctx, *didStr, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting transfer: %v\n", err)
		os.Exit(1)
	}

	if err := saveCustody(*didStr); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save new custody key: %v\n", err)
	}
	if err := SaveOpening(*didStr, opening); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save control opening: %v\n", err)
	}

	fmt.Printf("Control transferred: %s\n", resp.DID)
	fmt.Printf("New era: %d (effective %s)\n", nextEra, effectiveAt)
	fmt.Printf("CID: %s\n", resp.CID)
}
