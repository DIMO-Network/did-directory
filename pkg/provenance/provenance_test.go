package provenance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const relay = "did:dimo:flespi"

// directory serves one DID document per DID, each with a #signing key.
type directory map[string]*ecdsa.PrivateKey

func (d directory) Resolve(_ context.Context, id string) (*did.DIDDocument, error) {
	key, ok := d[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	pub, err := didkey.FromECDSA(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &did.DIDDocument{ID: id, VerificationMethod: []did.VerificationMethodEntry{
		{ID: id + "#signing", Type: "Multikey", Controller: id, PublicKeyMultibase: pub.Multibase()},
	}}, nil
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// machine returns a did:key machine and a signer for it.
func machine(t *testing.T) (string, Signer) {
	t.Helper()
	key := newKey(t)
	id, err := didkey.Encode(&key.PublicKey)
	require.NoError(t, err)
	return id, Signer{Key: key, KID: id + "#" + id[len("did:key:"):]}
}

type fixture struct {
	keys        DIDKeys
	relaySigner Signer
}

func newFixture(t *testing.T) fixture {
	relayKey := newKey(t)
	return fixture{
		keys:        DIDKeys{Directory: directory{relay: relayKey}},
		relaySigner: Signer{Key: relayKey, KID: relay + "#signing"},
	}
}

func header(producer string) Header {
	return Header{
		ID: "evt-1", Source: relay, Producer: producer, Subject: "did:dimo:car",
		Type: "dimo.status", Time: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC),
		DataVersion: "default/v1.0", DataContentType: "application/json",
	}
}

var data = []byte(`{"speed":42}`)

func sign(t *testing.T, s Signer, h Header, d []byte) string {
	t.Helper()
	jws, err := s.Sign(h, d)
	require.NoError(t, err)
	return jws
}

func TestVerify_RelayLabelsAMachineWithNoDID(t *testing.T) {
	f := newFixture(t)
	h := header("imei:356938035643809")

	kids, err := Verify(context.Background(), f.keys, h, data, Signatures{Source: sign(t, f.relaySigner, h, data)})
	require.NoError(t, err)
	assert.Equal(t, []string{relay + "#signing"}, kids)
}

func TestVerify_RelayAndMachineBothSign(t *testing.T) {
	f := newFixture(t)
	m, ms := machine(t)
	h := header(m)

	kids, err := Verify(context.Background(), f.keys, h, data, Signatures{
		Source: sign(t, f.relaySigner, h, data), Producer: sign(t, ms, h, data),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{relay + "#signing", ms.KID}, kids)
}

// A relay that produced the reading itself signs once.
func TestVerify_RelayIsItsOwnProducer(t *testing.T) {
	f := newFixture(t)
	h := header(relay)

	_, err := Verify(context.Background(), f.keys, h, data, Signatures{Source: sign(t, f.relaySigner, h, data)})
	assert.NoError(t, err)
}

// Naming a machine DID as the producer is a claim only the machine can make.
func TestVerify_DIDProducerMustSign(t *testing.T) {
	f := newFixture(t)
	m, _ := machine(t)
	h := header(m)
	relaySig := sign(t, f.relaySigner, h, data)

	_, err := Verify(context.Background(), f.keys, h, data, Signatures{Source: relaySig})
	assert.ErrorIs(t, err, ErrMissingSignature)

	// Nor can the relay sign in the machine's place.
	_, err = Verify(context.Background(), f.keys, h, data, Signatures{Source: relaySig, Producer: relaySig})
	assert.ErrorIs(t, err, ErrWrongSigner)
}

func TestVerify_SourceMustSign(t *testing.T) {
	f := newFixture(t)
	m, ms := machine(t)
	h := header(m)

	_, err := Verify(context.Background(), f.keys, h, data, Signatures{Producer: sign(t, ms, h, data)})
	assert.ErrorIs(t, err, ErrMissingSignature)

	// A machine's signature does not stand in for the relay's.
	_, err = Verify(context.Background(), f.keys, h, data, Signatures{Source: sign(t, ms, h, data), Producer: sign(t, ms, h, data)})
	assert.ErrorIs(t, err, ErrWrongSigner)
}

func TestVerify_NonDIDProducerCannotSign(t *testing.T) {
	f := newFixture(t)
	_, ms := machine(t)
	h := header("serial:A1")

	_, err := Verify(context.Background(), f.keys, h, data, Signatures{
		Source: sign(t, f.relaySigner, h, data), Producer: sign(t, ms, h, data),
	})
	assert.ErrorIs(t, err, ErrWrongSigner)
}

// Every bound field and the data itself are covered: a signed reading cannot
// be moved to another car, time or machine.
func TestVerify_TamperingBreaksBothSignatures(t *testing.T) {
	f := newFixture(t)
	m, ms := machine(t)
	h := header(m)
	sigs := Signatures{Source: sign(t, f.relaySigner, h, data), Producer: sign(t, ms, h, data)}

	tampered := map[string]func(*Header, *[]byte){
		"subject":     func(h *Header, _ *[]byte) { h.Subject = "did:dimo:other" },
		"time":        func(h *Header, _ *[]byte) { h.Time = h.Time.Add(time.Nanosecond) },
		"type":        func(h *Header, _ *[]byte) { h.Type = "dimo.event" },
		"id":          func(h *Header, _ *[]byte) { h.ID = "evt-2" },
		"dataversion": func(h *Header, _ *[]byte) { h.DataVersion = "default/v2.0" },
		"data":        func(_ *Header, d *[]byte) { *d = []byte(`{"speed":43}`) },
		"whitespace":  func(_ *Header, d *[]byte) { *d = []byte(`{"speed": 42}`) },
	}
	for name, mutate := range tampered {
		t.Run(name, func(t *testing.T) {
			h2, d2 := h, append([]byte(nil), data...)
			mutate(&h2, &d2)
			_, err := Verify(context.Background(), f.keys, h2, d2, sigs)
			assert.ErrorIs(t, err, ErrBadSignature)
		})
	}

	// The same instant in another zone is the same event.
	h2 := h
	h2.Time = h.Time.In(time.FixedZone("CEST", 2*60*60))
	_, err := Verify(context.Background(), f.keys, h2, data, sigs)
	assert.NoError(t, err)
}

func TestVerify_HeaderPicksNeitherKeyNorAlgorithm(t *testing.T) {
	f := newFixture(t)
	h := header("imei:1")
	jws := sign(t, f.relaySigner, h, data)
	_, sig, _ := strings.Cut(jws, "..")

	forge := func(hdr string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(hdr)) + ".." + sig
	}
	_, err := Verify(context.Background(), f.keys, h, data, Signatures{Source: forge(`{"alg":"ES256K","kid":"did:dimo:flespi#signing"}`)})
	assert.ErrorIs(t, err, ErrBadSignature)

	_, err = Verify(context.Background(), f.keys, h, data, Signatures{Source: forge(`{"alg":"ES256","kid":"did:dimo:flespi#other"}`)})
	assert.ErrorIs(t, err, ErrUnknownKey)
}

func TestSigningInput_RejectsLineBreaks(t *testing.T) {
	h := header("imei:1\nsubject=did:dimo:other")
	_, err := SigningInput(h, data)
	assert.ErrorIs(t, err, ErrInvalidHeader)

	h = header("imei:1")
	h.Subject = ""
	_, err = SigningInput(h, data)
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

// opaqueSigner hides the private key behind crypto.Signer, the way a KMS or
// HSM key looks to the code that uses it.
type opaqueSigner struct{ key *ecdsa.PrivateKey }

func (o opaqueSigner) Public() crypto.PublicKey { return &o.key.PublicKey }
func (o opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.key.Sign(r, digest, opts)
}

func TestSign_AnyCryptoSigner(t *testing.T) {
	key := newKey(t)
	keys := DIDKeys{Directory: directory{relay: key}}
	h := header("imei:1")

	jws := sign(t, Signer{Key: opaqueSigner{key}, KID: relay + "#signing"}, h, data)
	_, err := Verify(context.Background(), keys, h, data, Signatures{Source: jws})
	require.NoError(t, err)
}

func TestSign_RefusesOtherCurves(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = Signer{Key: key, KID: relay + "#signing"}.Sign(header("imei:1"), data)
	assert.ErrorContains(t, err, "P-256")
}
