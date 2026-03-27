package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/DIMO-Network/did-directory/pkg/client"
)

func runResolve(args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: dimocli resolve [flags] <did>\n")
		os.Exit(1)
	}

	didStr := fs.Arg(0)

	c := client.New(*server)
	c.SetVerbose(isVerbose())
	doc, err := c.Resolve(context.Background(), didStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving DID: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting document: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}
