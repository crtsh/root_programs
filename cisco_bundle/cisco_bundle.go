package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"go.mozilla.org/pkcs7"
)

func main() {
	p7Data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(fmt.Errorf("could not open %s", os.Args[1]))
	}

	p7, err := pkcs7.Parse(p7Data)
	if err != nil {
		panic(fmt.Errorf("could not parse %s", os.Args[1]))
	}

	p7Inner, err := pkcs7.Parse(p7.Content)
	if err != nil {
		panic(fmt.Errorf("could not parse content as PKCS#7 [%s]", os.Args[1]))
	}

	// Ensure that this root store update is atomic.
	fmt.Printf("BEGIN WORK;\n\n")
	fmt.Printf("LOCK TABLE root_trust_purpose;\n\n")
	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 13;\n\n")

	// Iterate through the certificates.
	for _, cert := range p7Inner.Certificates {
		sha256_cert := sha256.Sum256(cert.Raw)
		fmt.Printf("-- %s\n", cert.Subject.String())
		fmt.Printf("-- SHA-256: %s\n", strings.ToUpper(hex.EncodeToString(sha256_cert[:])))
		fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID ) SELECT import_cert(E'\\\\x%s'), 13, 1;\n\n", hex.EncodeToString(cert.Raw))
	}

	fmt.Printf("COMMIT WORK;\n")
}
