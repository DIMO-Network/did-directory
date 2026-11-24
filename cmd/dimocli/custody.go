package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	dimocrypto "github.com/DIMO-Network/did-directory/internal/crypto"
	"github.com/DIMO-Network/did-directory/internal/did"
	"github.com/DIMO-Network/did-directory/pkg/client"
)

// custodyProofHeader is the first line of the text a custody proof signs. It
// says what the signature is for, and, not being JSON, it can never be a DID
// operation, which is JSON, nor dauth's sign-in text.
const custodyProofHeader = "DIMO custody acceptance v1"

// errNoCustodyProof is a given custody key with no acceptance from its holder.
var errNoCustodyProof = errors.New("--new-custody-key needs --new-custody-proof: the new controller's signature with that key over the car, --to and the next era (dimocli custody-proof makes it)")

// custodyAcceptance is the text a new controller's custody key signs to accept
// a transfer (R3-F3): the header, then the car, the new controller of record
// and the era the transfer starts, one per line, with no trailing newline:
//
//	DIMO custody acceptance v1
//	Car: <car DID>
//	To: <new controller DID>
//	Era: <next era, decimal>
//
// The proof is the key's base64url r||s signature over the SHA-256 of these
// UTF-8 bytes, the form DID operations are signed in, so a Turnkey account
// makes one with sign_raw_payload (PAYLOAD_ENCODING_TEXT_UTF8,
// HASH_FUNCTION_SHA256).
func custodyAcceptance(car, to string, era uint64) []byte {
	return []byte(fmt.Sprintf("%s\nCar: %s\nTo: %s\nEra: %d", custodyProofHeader, car, to, era))
}

// verifyCustodyProof checks that proof is newKey's acceptance of car going to
// to at era. The key becomes the only one that can ever sign for the car
// again, so a key nobody holds (a typo: did:key has no checksum) or one
// meant for another transfer must stop here.
func verifyCustodyProof(newKey, proof, car, to string, era uint64) error {
	if proof == "" {
		return errNoCustodyProof
	}
	if err := dimocrypto.VerifyWithDIDKey(newKey, custodyAcceptance(car, to, era), proof); err != nil {
		return fmt.Errorf("the custody proof does not verify against --new-custody-key for %s to %s at era %d: check the key for typos, and that the proof was made for this car, controller and era", car, to, era)
	}
	return nil
}

// resolveController refuses a new controller of record the directory does not
// hold, or holds deactivated.
func resolveController(ctx context.Context, c *client.Client, to string) error {
	_, err := c.Resolve(ctx, to)
	switch {
	case errors.Is(err, client.ErrNotFound):
		return fmt.Errorf("--to %s is not in the directory", to)
	case errors.Is(err, client.ErrGone):
		return fmt.Errorf("--to %s is deactivated in the directory", to)
	case err != nil:
		return fmt.Errorf("resolving --to %s: %w", to, err)
	}
	return nil
}

// executeCustodyProof signs the custody acceptance with the key in the
// keystore-format file at path, P-256 or secp256k1, making a new P-256 key
// there first when generate is set (never over an existing file). It returns
// the key's did:key and the proof.
func executeCustodyProof(path string, generate bool, car, to string, era uint64) (string, string, error) {
	var s *fileSigner
	if generate {
		if _, err := os.Stat(path); err == nil {
			return "", "", fmt.Errorf("%s exists; --generate never overwrites a key", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", "", err
		}
		key, _, err := newKey()
		if err != nil {
			return "", "", err
		}
		if err := writeKey(path, car, key); err != nil {
			return "", "", err
		}
		if s, err = newFileSigner(key); err != nil {
			return "", "", err
		}
	} else {
		var err error
		if s, err = readSigner(path); err != nil {
			return "", "", err
		}
	}
	proof, err := s.Sign(context.Background(), custodyAcceptance(car, to, era))
	if err != nil {
		return "", "", err
	}
	return s.DIDKey(), proof, nil
}

// runCustodyProof is the new controller's half of a transfer: it prints the
// custody key and its acceptance for the seller's dimocli transfer.
func runCustodyProof(args []string) {
	fs := flag.NewFlagSet("custody-proof", flag.ExitOnError)
	server := fs.String("server", defaultServer(), "directory server URL, to read the car's next era when --era is not given")
	car := fs.String("car", "", "controlled DID being transferred (required)")
	to := fs.String("to", "", "new controller of record DID, as the seller will pass it (required)")
	eraFlag := fs.String("era", "", "era the transfer starts; default the car's current era plus one")
	keyFile := fs.String("key-file", "", "keystore-format key file holding the new custody key (required)")
	generate := fs.Bool("generate", false, "make a new P-256 custody key at --key-file (0600); never overwrites")
	fs.Parse(args)

	if *car == "" || *to == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --car, --to and --key-file are required")
		os.Exit(1)
	}
	if !did.IsValidDID(*car) || !did.IsValidDID(*to) {
		fmt.Fprintln(os.Stderr, "Error: --car and --to must be DIDs")
		os.Exit(1)
	}
	var era uint64
	if *eraFlag != "" {
		n, err := strconv.ParseUint(*eraFlag, 10, 64)
		if err != nil {
			fatal(fmt.Errorf("--era must be a non-negative integer"))
		}
		era = n
	} else {
		c := client.New(*server)
		c.SetVerbose(isVerbose())
		cur, err := currentEra(context.Background(), c, *car)
		if err != nil {
			fatal(err)
		}
		era = cur.Number + 1
	}
	key, proof, err := executeCustodyProof(*keyFile, *generate, *car, *to, era)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("New custody key: %s\n", key)
	fmt.Printf("Custody proof: %s\n", proof)
	fmt.Printf("For era %d. The seller runs:\n  dimocli transfer --did %s --to %s --new-custody-key %s --new-custody-proof %s\n", era, *car, *to, key, proof)
}
