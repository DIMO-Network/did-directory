package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/control"
)

// ErrNotFound is returned by Resolve and Control for a DID the directory does
// not hold. Callers that treat an unknown vehicle as "no control history"
// rather than as a failure match on it with errors.Is.
var ErrNotFound = errors.New("DID not found")

// Client is a Go client for the DID Directory service.
type Client struct {
	baseURL    string
	httpClient *http.Client
	verbose    bool
}

// New creates a new DID Directory client.
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetVerbose enables or disables verbose HTTP request/response logging.
func (c *Client) SetVerbose(v bool) {
	c.verbose = v
}

func (c *Client) logRequest(method, url string, body []byte) {
	if !c.verbose {
		return
	}
	fmt.Printf("\n\033[0;35m  ──── HTTP Request ────────────────────────────────────────────\033[0m\n")
	fmt.Printf("  \033[1m%s\033[0m %s\n", method, url)
	if len(body) > 0 {
		var pretty bytes.Buffer
		if json.Indent(&pretty, body, "  ", "  ") == nil {
			fmt.Printf("  %s\n", pretty.String())
		} else {
			fmt.Printf("  %s\n", truncate(string(body), 500))
		}
	}
}

func (c *Client) logResponse(status int, body []byte) {
	if !c.verbose {
		return
	}
	color := "\033[0;32m" // green
	if status >= 400 {
		color = "\033[0;31m" // red
	}
	fmt.Printf("\n\033[0;35m  ──── HTTP Response (%s%d\033[0;35m) ─────────────────────────────────────\033[0m\n", color, status)
	if len(body) > 0 {
		var pretty bytes.Buffer
		if json.Indent(&pretty, body, "  ", "  ") == nil {
			fmt.Printf("  %s\n", pretty.String())
		} else {
			fmt.Printf("  %s\n", truncate(string(body), 500))
		}
	}
	fmt.Printf("\033[0;35m  ─────────────────────────────────────────────────────────────\033[0m\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (c *Client) do(req *http.Request, reqBody []byte) (int, []byte, error) {
	c.logRequest(req.Method, req.URL.String(), reqBody)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	c.logResponse(resp.StatusCode, respBody)
	return resp.StatusCode, respBody, nil
}

// SubmitResponse is the response from submitting an operation.
type SubmitResponse struct {
	DID string `json:"did"`
	CID string `json:"cid"`
}

// Submit sends a signed operation to the directory.
func (c *Client) Submit(ctx context.Context, didStr string, op *did.Operation) (*SubmitResponse, error) {
	body, err := json.Marshal(op)
	if err != nil {
		return nil, fmt.Errorf("marshal operation: %w", err)
	}

	url := c.baseURL + "/" + didStr
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	status, respBody, err := c.do(req, body)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("submit failed (status %d): %s", status, string(respBody))
	}

	var result SubmitResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &result, nil
}

// Resolve fetches the DID Document for a given DID.
func (c *Client) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	url := c.baseURL + "/" + didStr
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	status, respBody, err := c.do(req, nil)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if status == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, didStr)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("resolve failed (status %d): %s", status, string(respBody))
	}

	var doc did.DIDDocument
	if err := json.Unmarshal(respBody, &doc); err != nil {
		return nil, fmt.Errorf("decode document: %w", err)
	}

	return &doc, nil
}

// Control fetches the control era history for a DID.
func (c *Client) Control(ctx context.Context, didStr string) (*control.State, error) {
	url := c.baseURL + "/" + didStr + "/control"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	status, respBody, err := c.do(req, nil)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if status == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, didStr)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("control lookup failed (status %d): %s", status, string(respBody))
	}

	var state control.State
	if err := json.Unmarshal(respBody, &state); err != nil {
		return nil, fmt.Errorf("decode control state: %w", err)
	}

	return &state, nil
}

// AuditLog fetches the full operation log for a DID.
func (c *Client) AuditLog(ctx context.Context, didStr string) ([]json.RawMessage, error) {
	url := c.baseURL + "/" + didStr + "/log/audit"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	status, respBody, err := c.do(req, nil)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("audit failed (status %d): %s", status, string(respBody))
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(respBody, &entries); err != nil {
		return nil, fmt.Errorf("decode audit log: %w", err)
	}

	return entries, nil
}

// RawGet performs a GET request and returns the raw response body.
func (c *Client) RawGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	status, respBody, err := c.do(req, nil)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("request failed (status %d): %s", status, string(respBody))
	}

	return respBody, nil
}

// RawPost performs a POST request with a JSON body and returns the raw response.
func (c *Client) RawPost(ctx context.Context, url string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return c.do(req, body)
}

// Health checks if the directory service is healthy.
func (c *Client) Health(ctx context.Context) error {
	url := c.baseURL + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Don't log health checks even in verbose mode — too noisy.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy (status %d)", resp.StatusCode)
	}

	return nil
}

// BaseURL returns the client's base URL.
func (c *Client) BaseURL() string {
	return strings.TrimSuffix(c.baseURL, "/")
}
