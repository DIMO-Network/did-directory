// Command didvectors writes the golden DID operation vectors as JSON.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/DIMO-Network/did-directory/internal/did"
)

func main() {
	out := flag.String("out", "testdata/vectors/did-ops.json", "output file")
	flag.Parse()

	f, err := did.GenerateVectors()
	if err != nil {
		log.Fatal(err)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
}
