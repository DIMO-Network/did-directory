package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

func runRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "DID to rotate keys for (required)")
	fs.Parse(args)

	if *didStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --did is required\n")
		os.Exit(1)
	}

	// Load the OLD private key.
	oldKey, err := LoadKey(*didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}

	// Generate a NEW P-256 private key.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating new key: %v\n", err)
		os.Exit(1)
	}

	newDIDKey, err := dimocrypto.EncodeDIDKey(&newKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding new did:key: %v\n", err)
		os.Exit(1)
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

	// Sign with OLD key.
	op, err := signOp(oldKey, buildRotate(currentOp, prevCID, newDIDKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	resp, err := c.Submit(ctx, *didStr, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting rotation: %v\n", err)
		os.Exit(1)
	}

	// Save the NEW key to keystore (overwriting old).
	if err := SaveKey(*didStr, newKey); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save new key: %v\n", err)
	}

	fmt.Printf("Keys rotated for: %s\n", resp.DID)
	fmt.Printf("CID: %s\n", resp.CID)
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
