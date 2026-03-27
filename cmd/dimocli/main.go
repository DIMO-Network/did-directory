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

func defaultAuthServer() string {
	if s := os.Getenv("AUTH_URL"); s != "" {
		return s
	}
	return "http://localhost:8081"
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
	case "revoke-all":
		runRevokeAll(args)
	case "sacd-grant":
		runSACDGrant(args)
	case "sacd-verify":
		runSACDVerify(args)
	case "auth":
		runAuth(args)
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
  create       Create a new DID
  resolve      Resolve a DID to its document
  update       Update a DID's service endpoints
  rotate       Rotate a DID's keys
  revoke-all   Bump SACD epoch to invalidate all grants
  sacd-grant   Create and sign an SACD document
  sacd-verify  Verify an SACD document
  auth         Authenticate and get a JWT
  pubkey       Print the did:key public key for a local DID

Environment:
  DIRECTORY_URL  Directory server URL (default: http://localhost:8080)
  AUTH_URL       Auth service URL (default: http://localhost:8081)
`)
}
