package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

func runRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "DID to rotate keys for (required)")
	toTurnkey := fs.Bool("to-turnkey", false, "move the root from the keystore into Turnkey: the wallet's next account becomes the rotation key and #signing")
	tk := bindTurnkeyFlags(fs)
	fs.Parse(args)

	if *didStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --did is required\n")
		os.Exit(1)
	}
	if err := tk.validate(); err != nil {
		fatal(err)
	}
	if *toTurnkey && !tk.enabled() {
		fatal(fmt.Errorf("--to-turnkey needs --turnkey-org, --turnkey-wallet and a Turnkey credential"))
	}

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	ctx := context.Background()

	// Get the latest CID and operation.
	prevCID, currentOp, err := getLatestCIDAndOp(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest state: %v\n", err)
		os.Exit(1)
	}
	// Before either key is touched: --to-turnkey would otherwise put an org's
	// root in the fleet wallet.
	if err := tk.refuseUnlessCar(currentOp.IsControlled()); err != nil {
		fatal(err)
	}

	// Sign with the OLD key: from the keystore when moving into Turnkey, else
	// wherever the flags say it lives.
	var oldSigner opSigner
	if *toTurnkey {
		oldSigner, err = resolveSigner(ctx, &turnkeyFlags{}, *didStr, currentOp, purposeUpdate)
	} else {
		oldSigner, err = resolveSigner(ctx, tk, *didStr, currentOp, purposeUpdate)
	}
	if err != nil {
		fatal(err)
	}

	// The NEW key: Turnkey's next account, or a fresh keystore key of the old
	// root's curve (secp256k1 for an org root, P-256 otherwise).
	current := ""
	if len(currentOp.RotationKeys) > 0 {
		current = currentOp.RotationKeys[0]
	}
	newDIDKey, saveNew, err := newCustodyLike(ctx, tk, current)
	if err != nil {
		fatal(err)
	}

	unsigned := buildRotate(currentOp, prevCID, newDIDKey)
	if *toTurnkey {
		unsigned = buildRotateTo(currentOp, prevCID, newDIDKey)
	}
	op, err := signOpWith(ctx, oldSigner, unsigned)
	if err != nil {
		fatal(err)
	}

	resp, err := c.Submit(ctx, *didStr, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting rotation: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Keys rotated for: %s\n", resp.DID)
	fmt.Printf("CID: %s\n", resp.CID)
	if tk.enabled() {
		fmt.Printf("New key held in Turnkey: %s\n", newDIDKey)
		if *toTurnkey {
			fmt.Printf("The old keystore key at %s no longer signs for this DID; remove it once you have confirmed the move.\n", keyFilePath(*didStr))
		}
		return
	}
	// Save the NEW key to keystore (overwriting old).
	if err := saveNew(*didStr); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save new key: %v\n", err)
	}
	fmt.Printf("New key stored at: %s\n", keyFilePath(*didStr))
}

// buildRotate replaces the rotation key and the #signing verification method
// with newDIDKey. Every other verification method stays: an org's #dimo_org
// commit key belongs to the org host and is rotated separately. A controlled
// DID only rotates its custody key; it never gains a verification method.
func buildRotate(current *did.Operation, prevCID, newDIDKey string) *did.UnsignedOperation {
	var vms map[string]string
	if !current.IsControlled() {
		vms = make(map[string]string, len(current.VerificationMethods)+1)
		for k, v := range current.VerificationMethods {
			vms[k] = v
		}
		vms["signing"] = newDIDKey
	}
	return &did.UnsignedOperation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{newDIDKey},
		VerificationMethods: vms,
		AlsoKnownAs:         current.AlsoKnownAs,
		Services:            current.Services,
		ControlCommitment:   current.ControlCommitment,
		Prev:                &prevCID,
	}
}

// buildRotateTo moves the root to newDIDKey (the Turnkey account): it replaces
// rotationKeys, and #signing only when that is the old rotation key, as it is
// for a dimocli org. Nothing else changes.
func buildRotateTo(current *did.Operation, prevCID, newDIDKey string) *did.UnsignedOperation {
	vms := current.VerificationMethods
	if len(current.RotationKeys) > 0 && vms["signing"] == current.RotationKeys[0] {
		vms = make(map[string]string, len(current.VerificationMethods))
		for k, v := range current.VerificationMethods {
			vms[k] = v
		}
		vms["signing"] = newDIDKey
	}
	return &did.UnsignedOperation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{newDIDKey},
		VerificationMethods: vms,
		AlsoKnownAs:         current.AlsoKnownAs,
		Services:            current.Services,
		ControlCommitment:   current.ControlCommitment,
		Prev:                &prevCID,
	}
}
