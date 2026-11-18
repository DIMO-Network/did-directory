// Package provenance signs and verifies who an event came from. An event about
// a vehicle reaches a store through a source (the relay that holds the write
// grant), which labels it with the producer (the machine that took the
// reading). The source always signs; a producer with a DID may sign too. Both
// signatures cover the same bytes: the header fields that say what the event
// is and who it is about, and a digest of the exact data bytes, so a signed
// reading cannot be replayed under another subject, time or producer.
//
// A signature is a compact JWS with a detached payload (RFC 7515 appendix F):
// "header..signature". The header names the verification method (kid) and the
// algorithm, ES256 for P-256 and ES256K for secp256k1, so any JOSE library can
// check one once it rebuilds the signing input.
package provenance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/multiformats/go-multicodec"
)

// Version names the signing input format. It is the first line of every
// signing input, so a signature over one format never verifies as another.
const Version = "dimo.event.v1"

// Extension attribute names under which a CloudEvent carries the signatures.
const (
	SourceSignatureAttr   = "sourcesignature"
	ProducerSignatureAttr = "producersignature"
)

var (
	// ErrInvalidHeader is a header that cannot be signed: a missing field, or
	// a field that would make the signing input ambiguous.
	ErrInvalidHeader = errors.New("invalid event header")
	// ErrMissingSignature is an event without a signature the rules require.
	ErrMissingSignature = errors.New("missing signature")
	// ErrWrongSigner is a signature by a key that does not belong to the party
	// it is supposed to be from.
	ErrWrongSigner = errors.New("signature is not by the expected party")
	// ErrBadSignature is a signature that does not verify.
	ErrBadSignature = errors.New("signature does not verify")
)

// Header is the part of an event the signatures bind. Field names follow the
// CloudEvents attributes they come from.
type Header struct {
	ID string
	// Source is the DID of the relay that holds the write grant and sent the
	// event in.
	Source string
	// Producer is the machine that took the reading: its DID when it has one,
	// otherwise an identifier the source assigns (an IMEI, a serial) that is
	// only meaningful together with Source.
	Producer        string
	Subject         string
	Type            string
	Time            time.Time
	DataVersion     string
	DataContentType string
}

// SigningInput returns the bytes both parties sign: one "name=value" line per
// header field, after the version line, and the SHA-256 of data last. Data is
// hashed as given, so a store that wants signatures to stay checkable must keep
// the exact bytes it received.
func SigningInput(h Header, data []byte) ([]byte, error) {
	for name, v := range map[string]string{"id": h.ID, "source": h.Source, "producer": h.Producer, "subject": h.Subject, "type": h.Type} {
		if v == "" {
			return nil, fmt.Errorf("%w: %s is empty", ErrInvalidHeader, name)
		}
	}
	if h.Time.IsZero() {
		return nil, fmt.Errorf("%w: time is zero", ErrInvalidHeader)
	}
	digest := sha256.Sum256(data)
	lines := []string{
		Version,
		"id=" + h.ID,
		"source=" + h.Source,
		"producer=" + h.Producer,
		"subject=" + h.Subject,
		"type=" + h.Type,
		"time=" + h.Time.UTC().Format(time.RFC3339Nano),
		"dataversion=" + h.DataVersion,
		"datacontenttype=" + h.DataContentType,
		"data=sha256:" + hex.EncodeToString(digest[:]),
	}
	var b strings.Builder
	for _, l := range lines {
		// A line break inside a value would let one field pass for another.
		if strings.ContainsAny(l, "\r\n") {
			return nil, fmt.Errorf("%w: %q contains a line break", ErrInvalidHeader, l)
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// Signer signs events with a P-256 key. KID is the verification method the
// key is published under: "<did>#signing" for a directory DID, or
// "<did:key>#<multibase>" for a did:key.
//
// Key is any crypto.Signer over P-256 that returns ASN.1 ECDSA signatures, as
// *ecdsa.PrivateKey does. A key held in a KMS or an HSM fits, so a relay's
// signing key need never leave it.
type Signer struct {
	Key crypto.Signer
	KID string
}

// Sign returns a detached compact JWS over the event's signing input.
func (s Signer) Sign(h Header, data []byte) (string, error) {
	if s.Key == nil {
		return "", errors.New("signer needs a P-256 key")
	}
	if pub, ok := s.Key.Public().(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return "", errors.New("signer needs a P-256 key")
	}
	if s.KID == "" {
		return "", errors.New("signer needs a kid")
	}
	input, err := SigningInput(h, data)
	if err != nil {
		return "", err
	}
	hdr, err := json.Marshal(jwsHeader{Alg: "ES256", KID: s.KID})
	if err != nil {
		return "", err
	}
	protected := base64.RawURLEncoding.EncodeToString(hdr)
	digest := sha256.Sum256(jwsInput(protected, input))
	der, err := s.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sig, err := rawSignature(der)
	if err != nil {
		return "", err
	}
	return protected + ".." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// rawSignature turns an ASN.1 ECDSA P-256 signature into the fixed-size r||s
// JWS uses (RFC 7518 section 3.4).
func rawSignature(der []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 {
		return nil, errors.New("signer returned a malformed ECDSA signature")
	}
	if rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return nil, errors.New("signer returned a signature that is not P-256")
	}
	sig := make([]byte, 64)
	rs.R.FillBytes(sig[:32])
	rs.S.FillBytes(sig[32:])
	return sig, nil
}

// Keys finds the public key behind a verification method.
type Keys interface {
	Key(ctx context.Context, kid string) (*didkey.PublicKey, error)
}

// Signatures are the two signatures an event may carry.
type Signatures struct {
	Source   string
	Producer string
}

// Verify checks an event's signatures against these rules:
//
//   - The source always signs, with a key of the source DID.
//   - A producer that is a DID other than the source must sign too, with a key
//     of its own. Otherwise a source could put words in a machine's mouth just
//     by writing its DID in the producer field.
//   - A producer signature on a producer that is not a DID is refused: there is
//     no key to check it against.
//
// It returns the kids that signed, source first.
func Verify(ctx context.Context, keys Keys, h Header, data []byte, sigs Signatures) ([]string, error) {
	if !isDID(h.Source) {
		return nil, fmt.Errorf("%w: source must be a DID", ErrInvalidHeader)
	}
	input, err := SigningInput(h, data)
	if err != nil {
		return nil, err
	}
	if sigs.Source == "" {
		return nil, fmt.Errorf("%w: source", ErrMissingSignature)
	}
	sourceKID, err := verifyOne(ctx, keys, h.Source, input, sigs.Source)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	kids := []string{sourceKID}

	producerSigns := isDID(h.Producer) && h.Producer != h.Source
	switch {
	case sigs.Producer == "" && producerSigns:
		return nil, fmt.Errorf("%w: producer %s is a DID", ErrMissingSignature, h.Producer)
	case sigs.Producer == "":
		return kids, nil
	case !isDID(h.Producer):
		return nil, fmt.Errorf("%w: producer %q is not a DID, so it cannot sign", ErrWrongSigner, h.Producer)
	}
	producerKID, err := verifyOne(ctx, keys, h.Producer, input, sigs.Producer)
	if err != nil {
		return nil, fmt.Errorf("producer: %w", err)
	}
	return append(kids, producerKID), nil
}

type jwsHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
}

func jwsInput(protected string, payload []byte) []byte {
	return []byte(protected + "." + base64.RawURLEncoding.EncodeToString(payload))
}

// verifyOne checks that jws is by a key of party over input, and returns its kid.
func verifyOne(ctx context.Context, keys Keys, party string, input []byte, jws string) (string, error) {
	protected, sig, ok := strings.Cut(jws, "..")
	if !ok || strings.Contains(sig, ".") {
		return "", fmt.Errorf("%w: not a detached compact JWS", ErrBadSignature)
	}
	raw, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return "", fmt.Errorf("%w: header: %v", ErrBadSignature, err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return "", fmt.Errorf("%w: header: %v", ErrBadSignature, err)
	}
	if did, _, _ := strings.Cut(hdr.KID, "#"); did != party {
		return "", fmt.Errorf("%w: kid %q is not a key of %s", ErrWrongSigner, hdr.KID, party)
	}
	pub, err := keys.Key(ctx, hdr.KID)
	if err != nil {
		return "", fmt.Errorf("key %s: %w", hdr.KID, err)
	}
	// The algorithm must be the key's, or a header could pick how its own
	// signature is checked.
	want := map[multicodec.Code]string{multicodec.P256Pub: "ES256", multicodec.Secp256k1Pub: "ES256K"}[pub.Codec()]
	if hdr.Alg != want {
		return "", fmt.Errorf("%w: alg %q for a %s key", ErrBadSignature, hdr.Alg, pub.Codec())
	}
	if err := pub.Verify(jwsInput(protected, input), sig); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return hdr.KID, nil
}

func isDID(s string) bool { return strings.HasPrefix(s, "did:") }
