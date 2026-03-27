package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	didStr := fs.String("did", "", "DID to update (required)")
	service := fs.String("service", "", "service endpoints as id=type:endpoint (comma-separated)")
	alias := fs.String("alias", "", "also-known-as aliases (comma-separated)")
	fs.Parse(args)

	if *didStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --did is required\n")
		os.Exit(1)
	}

	// Load private key from keystore.
	privKey, err := LoadKey(*didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}

	c := client.New(*server)
	ctx := context.Background()

	// Get the latest CID from audit log.
	prevCID, currentOp, err := getLatestCIDAndOp(ctx, c, *didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest state: %v\n", err)
		os.Exit(1)
	}

	// Build services map, starting from current.
	services := currentOp.Services
	if services == nil {
		services = make(map[string]did.Service)
	}
	if *service != "" {
		for _, s := range strings.Split(*service, ",") {
			parts := strings.SplitN(s, "=", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "Invalid service format: %s\n", s)
				os.Exit(1)
			}
			typeParts := strings.SplitN(parts[1], ":", 2)
			if len(typeParts) != 2 {
				fmt.Fprintf(os.Stderr, "Invalid service value: %s\n", parts[1])
				os.Exit(1)
			}
			services[parts[0]] = did.Service{
				Type:     typeParts[0],
				Endpoint: typeParts[1],
			}
		}
	}

	// Build aliases.
	aliases := currentOp.AlsoKnownAs
	if *alias != "" {
		aliases = strings.Split(*alias, ",")
	}

	// Build unsigned operation.
	unsignedOp := &did.UnsignedOperation{
		Type:                did.OpTypeCreate,
		RotationKeys:        currentOp.RotationKeys,
		VerificationMethods: currentOp.VerificationMethods,
		AlsoKnownAs:         aliases,
		Services:            services,
		Prev:                &prevCID,
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
		fmt.Fprintf(os.Stderr, "Error submitting update: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("DID updated: %s\n", resp.DID)
	fmt.Printf("CID: %s\n", resp.CID)
}

// getLatestCIDAndOp fetches the audit log and returns the latest CID and operation.
func getLatestCIDAndOp(ctx context.Context, c *client.Client, didStr string) (string, *did.Operation, error) {
	entries, err := c.AuditLog(ctx, didStr)
	if err != nil {
		return "", nil, fmt.Errorf("fetch audit log: %w", err)
	}
	if len(entries) == 0 {
		return "", nil, fmt.Errorf("no operations found for %s", didStr)
	}

	// Parse the last entry to get the CID and operation.
	var entry struct {
		CID       string        `json:"cid"`
		Operation did.Operation `json:"operation"`
	}
	if err := json.Unmarshal(entries[len(entries)-1], &entry); err != nil {
		return "", nil, fmt.Errorf("unmarshal audit entry: %w", err)
	}

	return entry.CID, &entry.Operation, nil
}
