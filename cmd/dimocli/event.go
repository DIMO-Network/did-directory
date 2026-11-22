package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/didkey"
	"github.com/DIMO-Network/did-directory/pkg/provenance"
	"github.com/google/uuid"
)

// runEvent prints a CloudEvent a source sends to din, signed by the source's
// #signing key from the keystore (docs/2026-10-24-sources.md). With
// --machine-key the producer is a machine with a did:key of its own, which
// signs too; the key file is created if it does not exist. Otherwise
// --producer is whatever the source calls the machine (an IMEI, a serial).
// --data goes into the event verbatim, since the signatures cover its bytes.
func runEvent(args []string) {
	fs := flag.NewFlagSet("event", flag.ExitOnError)
	didFlag := fs.String("did", "", "the source's DID (its key must be in the keystore)")
	subject := fs.String("subject", "", "the vehicle's DID")
	producer := fs.String("producer", "", "the machine, when it has no DID of its own")
	machineKey := fs.String("machine-key", "", "PEM P-256 key of a machine that signs as its did:key")
	ceType := fs.String("type", "dimo.status", "CloudEvent type")
	dataVersion := fs.String("dataversion", "default/v1.0", "CloudEvent dataversion")
	data := fs.String("data", "", "the event's data, JSON")
	at := fs.String("time", "", "the event's time, RFC 3339 (default: now)")
	fs.Parse(args)

	if *didFlag == "" || *subject == "" || *data == "" || (*producer == "") == (*machineKey == "") {
		fmt.Fprintln(os.Stderr, "Error: --did, --subject, --data and one of --producer or --machine-key are required")
		os.Exit(1)
	}
	if !json.Valid([]byte(*data)) {
		fmt.Fprintln(os.Stderr, "Error: --data is not JSON")
		os.Exit(1)
	}
	when := time.Now().UTC()
	if *at != "" {
		t, err := time.Parse(time.RFC3339Nano, *at)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: --time: %v\n", err)
			os.Exit(1)
		}
		when = t
	}
	out, err := signedEvent(*didFlag, *subject, *producer, *machineKey, *ceType, *dataVersion, *data, when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func signedEvent(source, subject, producer, machineKey, ceType, dataVersion, data string, when time.Time) (string, error) {
	sourceKey, err := LoadKey(source)
	if err != nil {
		return "", err
	}
	signers := []struct {
		signer provenance.Signer
		attr   string
	}{{provenance.Signer{Key: sourceKey, KID: source + "#signing"}, provenance.SourceSignatureAttr}}
	if machineKey != "" {
		key, err := loadOrCreatePEMKey(machineKey)
		if err != nil {
			return "", err
		}
		if producer, err = didkey.Encode(&key.PublicKey); err != nil {
			return "", err
		}
		kid := producer + "#" + strings.TrimPrefix(producer, "did:key:")
		signers = append(signers, struct {
			signer provenance.Signer
			attr   string
		}{provenance.Signer{Key: key, KID: kid}, provenance.ProducerSignatureAttr})
	}

	h := provenance.Header{
		ID: uuid.NewString(), Source: source, Producer: producer, Subject: subject,
		Type: ceType, Time: when, DataVersion: dataVersion, DataContentType: "application/json",
	}
	event := map[string]any{
		"specversion": "1.0", "id": h.ID, "source": h.Source, "producer": h.Producer,
		"subject": h.Subject, "type": h.Type, "time": h.Time.Format(time.RFC3339Nano),
		"dataversion": h.DataVersion, "datacontenttype": h.DataContentType,
	}
	for _, s := range signers {
		jws, err := s.signer.Sign(h, []byte(data))
		if err != nil {
			return "", err
		}
		event[s.attr] = jws
	}
	header, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(header), "}") + `,"data":` + data + "}", nil
}

// loadOrCreatePEMKey reads a SEC 1 PEM P-256 key, or makes one at path.
func loadOrCreatePEMKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := readSecretFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return key, writeSecretFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
