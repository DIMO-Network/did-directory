package dpop

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// htuVector is one entry of testdata/htu-vectors.json, the htu normalisation
// vectors the SDK tests too (cross-repo contract 4). Copy the file, don't
// fork it.
type htuVector struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

func readHTUVectors(t *testing.T) []htuVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/htu-vectors.json")
	require.NoError(t, err)
	var vs []htuVector
	require.NoError(t, json.Unmarshal(raw, &vs))
	require.Len(t, vs, 4)
	return vs
}

// R5-F9: Go and the SDK normalise htu identically: scheme and host
// lowercased, :443 dropped for https and :80 for http, query and fragment
// dropped, the path left byte for byte.
func TestNormalizeURI_ContractVectors(t *testing.T) {
	for _, v := range readHTUVectors(t) {
		assert.Equal(t, v.Out, NormalizeURI(v.In), "in %q", v.In)
		assert.Equal(t, v.Out, NormalizeURI(v.Out), "normalising is idempotent: %q", v.Out)
	}
}

func TestNormalizeURI_PathByteForByte(t *testing.T) {
	for in, want := range map[string]string{
		"https://X.test/A/B/":           "https://x.test/A/B/",
		"https://x.test/a%2Fb%20c":      "https://x.test/a%2Fb%20c",
		"https://x.test/a/../b":         "https://x.test/a/../b",
		"https://x.test//double":        "https://x.test//double",
		"https://x.test/a b":            "https://x.test/a%20b",
		"https://x.test":                "https://x.test",
		"https://x.test/":               "https://x.test/",
		"https://x.test:4430/p":         "https://x.test:4430/p",
		"https://x.test:80/p":           "https://x.test:80/p",
		"http://x.test:443/p":           "http://x.test:443/p",
		"https://[::1]:443/p":           "https://[::1]/p",
		"https://x.test:0443/p":         "https://x.test/p",
		"https://x.test:/p":             "https://x.test/p",
		"https://x.test:08080/p":        "https://x.test:8080/p",
		"https://x.test/p?next=http://": "https://x.test/p",
	} {
		assert.Equal(t, want, NormalizeURI(in), "in %q", in)
	}
}

// A client may sign the URL it was handed while its HTTP client escapes the
// request line; the proof still names the request.
func TestVerify_UnescapedURLMatchesTheWire(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	proof, err := key.Proof("PUT", "https://org.test/orgs/did:dimo:x/network.dimo.org.tag/a b", "", time.Now())
	require.NoError(t, err)
	_, err = NewVerifier().Verify(proof, "PUT", "https://org.test/orgs/did:dimo:x/network.dimo.org.tag/a%20b", "")
	assert.NoError(t, err)
}

// R5-F9's scenario: an operator configures the audience with an explicit
// default port, and the SDK signs the URL without it. Both name one URL.
func TestVerify_DefaultPortMatches(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	v := NewVerifier()
	proof, err := key.Proof("GET", "https://org-host.dimo.zone/orgs/x", "", time.Now())
	require.NoError(t, err)
	_, err = v.Verify(proof, "GET", "https://org-host.dimo.zone:443/orgs/x", "")
	assert.NoError(t, err)
}

// RFC 9449 matches htm exactly: a method is case-sensitive.
func TestVerify_HTMIsExact(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	v := NewVerifier()
	proof, err := key.Proof("get", "https://dq.test/query", "", time.Now())
	require.NoError(t, err)
	_, err = v.Verify(proof, "GET", "https://dq.test/query", "")
	require.ErrorIs(t, err, ErrInvalid)
	assert.Contains(t, err.Error(), "htm")

	proof, err = key.Proof("GET", "https://dq.test/query", "", time.Now())
	require.NoError(t, err)
	_, err = v.Verify(proof, "get", "https://dq.test/query", "")
	require.ErrorIs(t, err, ErrInvalid)

	proof, err = key.Proof("GET", "https://dq.test/query", "", time.Now())
	require.NoError(t, err)
	_, err = v.Verify(proof, "GET", "https://dq.test/query", "")
	assert.NoError(t, err)
}
