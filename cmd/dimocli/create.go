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
	"strings"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	service := fs.String("service", "", "service endpoints as id=type:endpoint (comma-separated)")
	alias := fs.String("alias", "", "also-known-as aliases (comma-separated)")
	rotationKeyDID := fs.String("rotation-key", "", "external rotation key (did:key format) to control this DID (e.g., owner's key for a vehicle DID)")
	fs.Parse(args)

	// Generate a P-256 private key.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}

	// Encode public key as did:key.
	didKey, err := dimocrypto.EncodeDIDKey(&privKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding did:key: %v\n", err)
		os.Exit(1)
	}

	// Determine rotation keys. If --rotation-key is provided, it becomes the
	// primary rotation key (highest authority), and the DID's own key is secondary.
	// This lets an external entity (e.g., vehicle owner) control the DID.
	rotationKeys := []string{didKey}
	if *rotationKeyDID != "" {
		if _, err := dimocrypto.DecodeDIDKey(*rotationKeyDID); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --rotation-key: %v\n", err)
			os.Exit(1)
		}
		rotationKeys = []string{*rotationKeyDID, didKey}
	}

	// Build services map.
	services := make(map[string]did.Service)
	if *service != "" {
		for _, s := range strings.Split(*service, ",") {
			parts := strings.SplitN(s, "=", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "Invalid service format: %s (expected id=type:endpoint)\n", s)
				os.Exit(1)
			}
			typeParts := strings.SplitN(parts[1], ":", 2)
			if len(typeParts) != 2 {
				fmt.Fprintf(os.Stderr, "Invalid service value: %s (expected type:endpoint)\n", parts[1])
				os.Exit(1)
			}
			services[parts[0]] = did.Service{
				Type:     typeParts[0],
				Endpoint: typeParts[1],
			}
		}
	}

	// Build aliases.
	var aliases []string
	if *alias != "" {
		aliases = strings.Split(*alias, ",")
	}

	// Build unsigned operation.
	unsignedOp := &did.UnsignedOperation{
		Type:                did.OpTypeCreate,
		RotationKeys:        rotationKeys,
		VerificationMethods: map[string]string{"signing": didKey},
		AlsoKnownAs:         aliases,
		Services:            services,
		Prev:                nil,
	}

	// Build signed operation for DID derivation (needs Operation type).
	op := &did.Operation{
		Type:                unsignedOp.Type,
		RotationKeys:        unsignedOp.RotationKeys,
		VerificationMethods: unsignedOp.VerificationMethods,
		AlsoKnownAs:         unsignedOp.AlsoKnownAs,
		Services:            unsignedOp.Services,
		Prev:                unsignedOp.Prev,
	}

	// Derive the DID.
	derivedDID, err := did.DeriveFromGenesis(op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving DID: %v\n", err)
		os.Exit(1)
	}

	// Sign the operation.
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
	op.Sig = sig

	// Submit to directory.
	c := client.New(*server)
	c.SetVerbose(isVerbose())
	resp, err := c.Submit(context.Background(), derivedDID, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error submitting operation: %v\n", err)
		os.Exit(1)
	}

	// Save key to keystore.
	if err := SaveKey(derivedDID, privKey); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save key: %v\n", err)
	}

	fmt.Printf("DID created: %s\n", resp.DID)
	fmt.Printf("CID: %s\n", resp.CID)
	fmt.Printf("Key stored at: %s\n", keyFilePath(derivedDID))
}
