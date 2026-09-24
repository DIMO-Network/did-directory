// Package booking is the booking service's side of the org host: the SDK an
// operator links to turn its agreements into records on its host (plan §5 and
// §6 step 5, decision F).
//
// The host is generic and never learns what a booking is. This package
// compiles an agreement with agreement.Compile, writes each grant to the
// operator's repository as an ODRL policy under its stable key and each custody leg under its
// own, and tombstones the grants an earlier compilation produced that this one
// no longer does. Every write is made as the booking service, with the
// identity token of the DID its booking role was written to, so the host's
// role and policy checks are what bound it.
//
// Sync is idempotent: the same agreement at the same instant produces the same
// writes, so a caller that fails partway simply calls it again. The clock is a
// parameter, as it is for Compile, and no state is kept between calls: what to
// revoke is derived from the agreement (agreement.Keys), not remembered.
package booking

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/agreement"
	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
)

// OpPending is the Outcome.Op of a write the host parked for a second
// approval. Nothing is committed until somebody approves it. A booking role
// committing under agreement.CommitPolicy does not see this for the grants a
// booking compiles to; a role under the default policy sees it for every live
// ability, which is the host telling the operator its booking role is set up
// wrong.
const OpPending = "pending"

// Client writes to one org host as a booking service.
type Client struct {
	// Host is the org host's base URL, without a trailing slash: what the
	// operator's DID publishes as its #dimo_org_host service entry.
	Host string
	// Token supplies the booking service's identity token (plan §1 decision B).
	// It is called before every request, because tokens expire and a booking
	// service runs for longer than one lasts. StaticToken wraps a fixed one.
	Token func(ctx context.Context) (string, error)
	// HTTP is the client to send with; nil means http.DefaultClient.
	HTTP *http.Client
}

// StaticToken is a Token that always answers the same string, for tests and
// short-lived tools.
func StaticToken(token string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return token, nil }
}

// Error is a refusal from the host: the status it answered and what it said.
type Error struct {
	Status  int
	Method  string
	Path    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("org host: %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

// Outcome is the host's answer to one write.
type Outcome struct {
	// Key is the record key written, and URI the record's address.
	Key string
	URI string
	// Op is what the host did: create, update or tombstone, or OpPending.
	Op string
	// CID and Rev identify the commit, when there was one.
	CID string
	Rev string
	// Pending is the pending write's id and Reasons the host's reasons, when Op
	// is OpPending.
	Pending string
	Reasons []string
}

// Result is what one Sync did on the host.
type Result struct {
	// Custody are the custody legs written, in the agreement's order.
	Custody []Outcome
	// Grants are the compiled grants written, in Compile's order.
	Grants []Outcome
	// Revoked are the grants an earlier compilation produced and this one did
	// not, now tombstoned.
	Revoked []Outcome
}

// CustodyKey is the record key of a custody leg: the booking it belongs to and
// when the leg began, which is what identifies a leg once the return syncs and
// the same key is written again with its end. The agreement's ID must be drawn
// from the alphabet Agreement.ID requires.
func CustodyKey(bookingID string, start time.Time) string {
	return bookingID + agreement.KeySeparator + start.UTC().Format("20060102T150405.000000000Z")
}

// Sync brings the host's records for agreement a into line with its state at
// time now: every custody leg is written under CustodyKey, every grant
// Compile produces under its Grant.Key, and every key agreement.Keys lists
// that Compile did not produce is tombstoned if it is live. Custody goes
// first, since it is what the grants narrow by; grants before tombstones, so a
// customer never loses a record before its replacement lands.
//
// The writes go to the repository of the agreement's assigner, the operator.
// A failure stops the sync where it happened and returns the error, the
// host's own as an *Error; the writes before it stand, and calling again
// finishes the job.
func (c *Client) Sync(ctx context.Context, a *agreement.Agreement, cat agreement.Catalog, now time.Time) (*Result, error) {
	grants, err := agreement.Compile(a, cat, now)
	if err != nil {
		return nil, err
	}
	keys, err := agreement.Keys(a, cat)
	if err != nil {
		return nil, err
	}
	org := a.Assigner
	res := &Result{}

	// A leg without a vehicle cannot exist: the vehicle is assigned before
	// anyone takes it. Custody is written whether or not the booking compiles to
	// anything, because it is a fact about the car, not a product of the sale.
	if a.Target.Vehicle != "" {
		for i := range a.Custody {
			leg := &a.Custody[i]
			period := delegation.CustodyPeriod{Vehicle: a.Target.Vehicle, Holder: a.Assignee, From: leg.Start, Until: leg.End}
			out, err := c.put(ctx, org, delegation.CollectionCustody, CustodyKey(a.ID, leg.Start), period)
			if err != nil {
				return nil, err
			}
			res.Custody = append(res.Custody, *out)
		}
	}

	produced := make(map[string]bool, len(grants))
	for i := range grants {
		g := &grants[i]
		produced[g.Key] = true
		// A grant crosses the wire as the ODRL policy it is (spec §5).
		policy, err := odrl.ToPolicy(&g.Record, "at://"+org+"/"+delegation.CollectionDelegation+"/"+g.Key)
		if err != nil {
			return nil, fmt.Errorf("grant %s: %w", g.Key, err)
		}
		out, err := c.put(ctx, org, delegation.CollectionDelegation, g.Key, policy)
		if err != nil {
			return nil, err
		}
		res.Grants = append(res.Grants, *out)
	}

	for _, key := range keys {
		if produced[key] {
			continue
		}
		out, err := c.revoke(ctx, org, delegation.CollectionDelegation, key)
		if err != nil {
			return nil, err
		}
		if out != nil {
			res.Revoked = append(res.Revoked, *out)
		}
	}
	return res, nil
}

// put creates or updates one record.
func (c *Client) put(ctx context.Context, org, collection, rkey string, record any) (*Outcome, error) {
	path := recordPath(org, collection, rkey)
	status, body, err := c.do(ctx, http.MethodPut, path, record)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK, http.StatusCreated:
		return outcome(rkey, body)
	case http.StatusAccepted:
		var parked struct {
			Pending string   `json:"pending"`
			URI     string   `json:"uri"`
			Reasons []string `json:"reasons"`
		}
		if err := json.Unmarshal(body, &parked); err != nil {
			return nil, fmt.Errorf("org host: PUT %s: decode response: %w", path, err)
		}
		return &Outcome{Key: rkey, URI: parked.URI, Op: OpPending, Pending: parked.Pending, Reasons: parked.Reasons}, nil
	default:
		return nil, refused(http.MethodPut, path, status, body)
	}
}

// revoke tombstones a record if it is live, and returns nil when there is
// nothing to do: the key was never written, or is tombstoned already.
func (c *Client) revoke(ctx context.Context, org, collection, rkey string) (*Outcome, error) {
	live, err := c.live(ctx, org, collection, rkey)
	if err != nil || !live {
		return nil, err
	}
	path := recordPath(org, collection, rkey)
	status, body, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		return outcome(rkey, body)
	case http.StatusNotFound:
		return nil, nil
	case http.StatusConflict:
		// Either somebody tombstoned it between the read and the delete, which
		// is the outcome asked for, or the repository is contended. Ask again
		// rather than read the host's message.
		live, err := c.live(ctx, org, collection, rkey)
		if err != nil || !live {
			return nil, err
		}
		return nil, refused(http.MethodDelete, path, status, body)
	default:
		return nil, refused(http.MethodDelete, path, status, body)
	}
}

// live reports whether the record exists and is not tombstoned.
func (c *Client) live(ctx context.Context, org, collection, rkey string) (bool, error) {
	path := recordPath(org, collection, rkey)
	status, body, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusGone:
		return false, nil
	default:
		return false, refused(http.MethodGet, path, status, body)
	}
}

// do sends one request with the booking service's token and returns the
// status and body. Only transport failures are errors here; what a status
// means is the caller's to decide.
func (c *Client) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.Host, "/")+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token == nil {
		return 0, nil, errors.New("booking: Client.Token is required")
	}
	token, err := c.Token(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("identity token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read %s %s: %w", method, path, err)
	}
	return resp.StatusCode, raw, nil
}

func recordPath(org, collection, rkey string) string {
	return "/orgs/" + url.PathEscape(org) + "/" + url.PathEscape(collection) + "/" + url.PathEscape(rkey)
}

// outcome decodes a committed write's response.
func outcome(rkey string, body []byte) (*Outcome, error) {
	var res struct {
		URI string `json:"uri"`
		CID string `json:"cid"`
		Rev string `json:"rev"`
		Op  string `json:"op"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("org host: decode write response: %w", err)
	}
	return &Outcome{Key: rkey, URI: res.URI, Op: res.Op, CID: res.CID, Rev: res.Rev}, nil
}

// refused builds the Error for a status the caller did not expect, carrying
// the host's message when it sent one.
func refused(method, path string, status int, body []byte) error {
	var msg struct {
		Error string `json:"error"`
	}
	message := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &msg) == nil && msg.Error != "" {
		message = msg.Error
	}
	return &Error{Status: status, Method: method, Path: path, Message: message}
}
