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
	case "custody-proof":
		runCustodyProof(args)
	case "revoke-since":
		runRevokeSince(args)
	case "pubkey":
		runPubkey(args)
	case "signin":
		runSignin(args)
	case "dpop":
		runDPoP(args)
	case "exchange":
		runExchange(args)
	case "query":
		runQuery(args)
	case "booking":
		runBooking(args)
	case "verify-proof":
		runVerifyProof(args)
	case "event":
		runEvent(args)
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
  transfer     Transfer a controlled DID to a new controller (starts a new era); a
               custody key the new controller supplies needs its --new-custody-proof
  custody-proof
               As the new controller: sign the acceptance of a transfer with the new
               custody key from a key file (--generate makes one), for the seller
  revoke-since Record a compromise window and rotate the custody key
  pubkey       Print the did:key public key for a local DID (--org for its #dimo_org key)
  signin       Sign in to dauth as a local DID and print the identity token: --scope
               says what it may do, and it is bound to the DID's #signing key
  dpop         Print the DPoP proof one request presenting a signin token must carry
  exchange     Sign in, prove the DID's key with DPoP and mint an access token from dauth
               for one delegation over one vehicle
  query        Mint an access token as exchange does, then send a GraphQL query to dq
               with it and a DPoP proof for the request
  booking      Sync an agreement JSON to the operator's org host as the booking service
  verify-proof Verify a coverage proof offline against the directory's keys and era log
  event        Print a CloudEvent signed by a source (and by a did:key machine with
               --machine-key), ready to send to din

Environment:
  DIRECTORY_URL  Directory server URL (default: http://localhost:8080)
  DAUTH_URL      dauth base URL for signin (default: http://localhost:8080)
  DQ_URL         dq base URL for query (default: http://localhost:3000)
`)
}
