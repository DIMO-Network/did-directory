package main

import (
	"fmt"
	"os"
)

func isVerbose() bool {
	return os.Getenv("DIMO_VERBOSE") == "1"
}

func defaultServer() string {
	if s := os.Getenv("DIRECTORY_URL"); s != "" {
		return s
	}
	return "http://localhost:8080"
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "create":
		runCreate(args)
	case "resolve":
		runResolve(args)
	case "update":
		runUpdate(args)
	case "rotate":
		runRotate(args)
	case "transfer":
		runTransfer(args)
	case "revoke-since":
		runRevokeSince(args)
	case "pubkey":
		runPubkey(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `dimocli - DIMO DID Directory CLI

Usage:
  dimocli <command> [flags]

Commands:
  create       Create a new DID (--controller for a controlled asset such as a vehicle,
               --org for an org with a #dimo_org commit key and --org-host)
  resolve      Resolve a DID to its document
  update       Update a DID's service endpoints, #dimo_org key or #dimo_org_host
  rotate       Rotate a DID's keys
  transfer     Transfer a controlled DID to a new controller (starts a new era)
  revoke-since Record a compromise window and rotate the custody key
  pubkey       Print the did:key public key for a local DID (--org for its #dimo_org key)

Environment:
  DIRECTORY_URL  Directory server URL (default: http://localhost:8080)
`)
}
