package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/agreement/booking"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

// runBooking is a booking service in one command: it reads an agreement,
// signs in to dauth as the booking service DID and syncs the agreement to the
// operator's org host through pkg/agreement/booking, under the rental catalog
// (spec §12.1). The host never learns what a booking is; this is the client
// side of decision F, driven from a file so a shell can move an agreement
// through its lifecycle.
func runBooking(args []string) {
	fs := flag.NewFlagSet("booking", flag.ExitOnError)
	dauth := fs.String("dauth", defaultDauth(), "dauth base URL")
	server := fs.String("server", defaultServer(), "directory server URL, to find the operator's org host")
	host := fs.String("host", "", "org host base URL; default is the assigner's #dimo_org_host service entry")
	didFlag := fs.String("did", "", "booking service DID, the holder of the booking role (its key must be in the keystore)")
	file := fs.String("agreement", "", "path to the agreement JSON")
	nowFlag := fs.String("now", "", "compile at this RFC 3339 time instead of now")
	_ = fs.Parse(args)

	if *didFlag == "" || *file == "" {
		fmt.Fprintln(os.Stderr, "Error: --did and --agreement are required")
		os.Exit(1)
	}
	now := time.Now().UTC()
	if *nowFlag != "" {
		t, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: --now: %v\n", err)
			os.Exit(1)
		}
		now = t
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	var a agreement.Agreement
	if err := json.Unmarshal(data, &a); err != nil {
		fmt.Fprintf(os.Stderr, "Error: parse agreement: %v\n", err)
		os.Exit(1)
	}
	if err := a.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: agreement: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if *host == "" {
		if *host, err = orgHostOf(ctx, *server, a.Assigner); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	priv, err := LoadKey(*didFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	token, _, err := signIn(*dauth, *didFlag, priv, "signing", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: sign in as %s: %v\n", *didFlag, err)
		os.Exit(1)
	}

	c := &booking.Client{Host: strings.TrimRight(*host, "/"), Token: booking.StaticToken(token)}
	res, err := c.Sync(ctx, &a, agreement.RentalCatalog(), now)
	if err != nil {
		var refusal *booking.Error
		if errors.As(err, &refusal) {
			fmt.Fprintf(os.Stderr, "Error: the org host refused: %v\n", refusal)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
	report := func(kind string, outs []booking.Outcome) {
		for _, o := range outs {
			if o.Op == booking.OpPending {
				fmt.Printf("%-8s %-40s pending %s (%s)\n", kind, o.Key, o.Pending, strings.Join(o.Reasons, "; "))
				continue
			}
			fmt.Printf("%-8s %-40s %-9s %s\n", kind, o.Key, o.Op, o.URI)
		}
	}
	report("custody", res.Custody)
	report("grant", res.Grants)
	report("revoked", res.Revoked)
	if len(res.Custody)+len(res.Grants)+len(res.Revoked) == 0 {
		fmt.Println("nothing to write: the agreement compiles to no records at this time")
	}
}

// orgHostOf resolves org's DID document and returns its #dimo_org_host
// service endpoint.
func orgHostOf(ctx context.Context, server, org string) (string, error) {
	c := client.New(server)
	c.SetVerbose(isVerbose())
	doc, err := c.Resolve(ctx, org)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", org, err)
	}
	for _, s := range doc.Service {
		if strings.HasSuffix(s.ID, "#"+OrgHostServiceID) && s.ServiceEndpoint != "" {
			return s.ServiceEndpoint, nil
		}
	}
	return "", fmt.Errorf("%s publishes no #%s service entry; pass --host", org, OrgHostServiceID)
}
