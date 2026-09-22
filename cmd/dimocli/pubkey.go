package main

import (
	"flag"
	"fmt"
	"os"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
)

func runPubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	org := fs.Bool("org", false, "print the org's #dimo_org commit signing key instead")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: dimocli pubkey [--org] <did>")
		os.Exit(1)
	}

	didStr := fs.Arg(0)

	load := LoadKey
	if *org {
		load = LoadOrgKey
	}
	privKey, err := load(didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key for %s: %v\n", didStr, err)
		os.Exit(1)
	}

	didKey, err := dimocrypto.EncodeDIDKey(&privKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding did:key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(didKey)
}
