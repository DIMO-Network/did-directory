package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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

	// Build update with new keys.
	unsignedOp := &did.UnsignedOperation{
		Type:                did.OpTypeCreate,
		RotationKeys:        []string{newDIDKey},
		VerificationMethods: map[string]string{"signing": newDIDKey},
		AlsoKnownAs:         currentOp.AlsoKnownAs,
		Services:            currentOp.Services,
		Prev:                &prevCID,
	}

	// Sign with OLD key.
	data, err := json.Marshal(unsignedOp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling operation: %v\n", err)
		os.Exit(1)
	}

	sig, err := dimocrypto.SignOperation(oldKey, data)
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
		Prev:                unsignedOp.Prev,
		Sig:                 sig,
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
