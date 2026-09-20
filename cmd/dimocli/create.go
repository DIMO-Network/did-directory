package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/control"
)

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	service := fs.String("service", "", "service endpoints as id=type:endpoint (comma-separated)")
	alias := fs.String("alias", "", "also-known-as aliases (comma-separated)")
	controller := fs.String("controller", "", "controller of record DID; creates a controlled asset DID (e.g., a vehicle) with no signing key")
	fs.Parse(args)

	// Generate a P-256 private key. For a controlled DID this is the per-vehicle
	// custody key held by the controller; it only authorizes DID operations.
	privKey, didKey, err := newKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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

	unsignedOp := &did.UnsignedOperation{
		Type:         did.OpTypeCreate,
		RotationKeys: []string{didKey},
		AlsoKnownAs:  aliases,
		Services:     services,
		Prev:         nil,
	}

	var opening *control.Opening
	if *controller != "" {
		if !did.IsValidDID(*controller) {
			fmt.Fprintf(os.Stderr, "Invalid --controller: %s\n", *controller)
			os.Exit(1)
		}
		o, commitment, err := newCommitment(*controller, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating control commitment: %v\n", err)
			os.Exit(1)
		}
		unsignedOp.ControlCommitment = &commitment
		opening = &o
	} else {
		unsignedOp.VerificationMethods = map[string]string{"signing": didKey}
	}

	op, err := signOp(privKey, unsignedOp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Derive the DID.
	derivedDID, err := did.DeriveFromGenesis(op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving DID: %v\n", err)
		os.Exit(1)
	}

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

	if opening != nil {
		if err := SaveOpening(derivedDID, *opening); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save control opening: %v\n", err)
		}
		fmt.Printf("Controller of record: %s (era 0, not published)\n", opening.Controller)
		fmt.Printf("Control commitment: %s\n", *unsignedOp.ControlCommitment)
		fmt.Printf("Control opening stored at: %s\n", openingFilePath(derivedDID))
	}
}
