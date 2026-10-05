package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// runQuery is a data consumer in one command: it mints an access token for
// one delegation over one vehicle (as exchange does), then sends a GraphQL
// query to dq with that token and a DPoP proof for the request, signed by the
// same key the token is bound to. dq clamps the query to the windows the
// token carries (spec §11.4), so what comes back is what the delegation
// actually allows, not what was asked for.
func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL, as dauth publishes it (its PUBLIC_BASE_URL)")
	dq := fs.String("dq", defaultDQ(), "dq base URL, as dq checks DPoP proofs against (its PUBLIC_BASE_URL)")
	didFlag := fs.String("did", "", "caller DID (its key must be in the keystore)")
	grant := fs.String("grant", "", "at:// URI of the delegation to exercise; omit to act as the vehicle's controller")
	vehicle := fs.String("vehicle", "", "vehicle DID")
	abilities := fs.String("abilities", "", "abilities to request (comma-separated)")
	client := fs.String("client", "", "app DID to attest as client_assertion (its key must be in the keystore)")
	query := fs.String("query", "", "GraphQL query; $subject is bound to the vehicle DID")
	variables := fs.String("variables", "", "extra GraphQL variables as a JSON object")
	_ = fs.Parse(args)

	if *didFlag == "" || *vehicle == "" || *abilities == "" || *query == "" {
		fmt.Fprintln(os.Stderr, "Error: --did, --vehicle, --abilities and --query are required")
		os.Exit(1)
	}
	vars := map[string]any{}
	if *variables != "" {
		if err := json.Unmarshal([]byte(*variables), &vars); err != nil {
			fmt.Fprintf(os.Stderr, "Error: --variables: %v\n", err)
			os.Exit(1)
		}
	}
	vars["subject"] = *vehicle

	access, err := mintAccessToken(*dauth, exchangeRequest{
		Caller: *didFlag, Grant: *grant, Vehicle: *vehicle, Abilities: strings.Split(*abilities, ","), Client: *client,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	queryURL := strings.TrimRight(*dq, "/") + "/query"
	proof, err := dpopProof(access.key, "POST", queryURL, access.Token, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: DPoP proof: %v\n", err)
		os.Exit(1)
	}
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	headers := map[string]string{"Authorization": "DPoP " + access.Token, "DPoP": proof}
	if err := sendJSON("POST", queryURL, headers, map[string]any{"query": *query, "variables": vars}, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: POST /query: %v\n", err)
		os.Exit(1)
	}
	if len(resp.Errors) > 0 {
		// GraphQL answers 200 with errors; a refused directive is one of them.
		// Print what data there is, then the errors, and fail.
		if len(resp.Data) > 0 && string(resp.Data) != "null" {
			fmt.Println(string(resp.Data))
		}
		for _, e := range resp.Errors {
			fmt.Fprintf(os.Stderr, "Error: dq: %s\n", e.Message)
		}
		os.Exit(1)
	}
	fmt.Println(string(resp.Data))
}

func defaultDQ() string {
	if v := os.Getenv("DQ_URL"); v != "" {
		return v
	}
	return "http://localhost:3000"
}
