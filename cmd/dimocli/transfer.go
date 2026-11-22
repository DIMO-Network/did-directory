package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
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
	newCustodyKey := fs.String("new-custody-key", "", "did:key of the custody key the new controller supplies; required with Turnkey, else one is generated and stored locally")
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
	if err := executeTransfer(context.Background(), c, tk, *didStr, *to, *newCustodyKey, os.Stdout); err != nil {
		fatal(err)
	}
}

// executeTransfer signs a transfer of didStr to the controller `to`. newKey is
// the new controller's custody did:key; empty means generate one into the
// keystore, which Turnkey signing refuses: the key must be the buyer's, not one
// created in the seller's wallet.
func executeTransfer(ctx context.Context, c *client.Client, tk *turnkeyFlags, didStr, to, newKey string, out io.Writer) error {
	if tk.enabled() && newKey == "" {
		return errors.New("a Turnkey transfer needs --new-custody-key from the new controller")
	}
	if newKey != "" {
		if _, err := dimocrypto.DecodeDIDKey(newKey); err != nil {
			return fmt.Errorf("--new-custody-key: %w", err)
		}
	}

	cur, err := currentEra(ctx, c, didStr)
	if err != nil {
		return err
	}
	prevCID, currentOp, err := getLatestCIDAndOp(ctx, c, didStr)
	if err != nil {
		return fmt.Errorf("getting latest state: %w", err)
	}

	custodySigner, err := resolveSigner(ctx, tk, didStr, currentOp, purposeTransfer)
	if err != nil {
		return err
	}
	newCustodyDIDKey, saveCustody := newKey, func(string) error { return nil }
	if newKey == "" {
		newCustodyDIDKey, saveCustody, err = newCustody(ctx, tk)
		if err != nil {
			return err
		}
	}
	nextEra := cur.Number + 1
	opening, commitment, err := newCommitment(to, nextEra)
	if err != nil {
		return fmt.Errorf("creating control commitment: %w", err)
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
		return err
	}

	resp, err := c.Submit(ctx, didStr, op)
	if err != nil {
		return fmt.Errorf("submitting transfer: %w", err)
	}

	if err := saveCustody(didStr); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save new custody key: %v\n", err)
	}
	if err := SaveOpening(didStr, opening); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save control opening: %v\n", err)
	}

	fmt.Fprintf(out, "Control transferred: %s\n", resp.DID)
	fmt.Fprintf(out, "New era: %d (effective %s)\n", nextEra, effectiveAt)
	fmt.Fprintf(out, "CID: %s\n", resp.CID)
	return nil
}
