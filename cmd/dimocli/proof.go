package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/proof"
)

// runVerifyProof checks a coverage proof offline (spec §11.3, plan §3.4): every
// commit in the bundle against its org's #dimo_org key, and the evaluation
// replayed over the bundle against the coverage the host claimed. The keys and
// the vehicle's era log are taken from the directory, not from the bundle, so
// the proof is checked against what the directory says today; --no-anchors
// uses the bundle's own copies instead, which shows only that the bundle is
// consistent with itself. The org host is not consulted.
func runVerifyProof(args []string) {
	fs := flag.NewFlagSet("verify-proof", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL, for the org keys and era log")
	file := fs.String("file", "", "path to the proof JSON as GET .../proof served it")
	noAnchors := fs.Bool("no-anchors", false, "trust the bundle's own keys and era log instead of the directory")
	_ = fs.Parse(args)

	if *file == "" {
		fmt.Fprintln(os.Stderr, "Error: --file is required")
		os.Exit(1)
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	var p proof.Proof
	if err := json.Unmarshal(data, &p); err != nil {
		fmt.Fprintf(os.Stderr, "Error: parse proof: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	var anchors proof.Anchors
	if !*noAnchors {
		c := client.New(*server)
		c.SetVerbose(isVerbose())
		if anchors, err = proof.DirectoryAnchors(ctx, c, &p); err != nil {
			fmt.Fprintf(os.Stderr, "Error: anchors from the directory: %v\n", err)
			os.Exit(1)
		}
	}
	cov, err := proof.Verify(ctx, &p, anchors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Proof does NOT verify: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Proof verifies: %s over %s at %s\n", p.Delegation, p.Vehicle, p.At.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Printf("Commits checked: %d, signed by %d org key(s)\n", len(p.Commits), len(p.Keys))
	out, err := json.MarshalIndent(cov, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
