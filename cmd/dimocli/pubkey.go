package main

import (
	"flag"
	"fmt"
	"os"
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

	didKey, err := pubkeyOf(didStr, *org)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key for %s: %v\n", didStr, err)
		os.Exit(1)
	}

	fmt.Println(didKey)
}
