package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/square/certigo/jceks"
	"os"
	"strings"
)

func main() {
	// Read and parse cacerts file.
	key_store, err := jceks.LoadFromFile(os.Args[1], nil)
	if err != nil {
		panic(err)
	}

	// Ensure that this root store update is atomic.
	fmt.Printf("BEGIN WORK;\n\n")
	fmt.Printf("LOCK TABLE root_trust_purpose;\n\n")
	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 23;\n\n")

	// Iterate through the certificates.
	var cert *x509.Certificate
	for _, alias := range key_store.ListCerts() {
		cert, err = key_store.GetCert(alias)
		if err != nil {
			panic(err)
		}

		sha256_cert := sha256.Sum256(cert.Raw)
		fmt.Printf("-- %s\n", cert.Subject.String())
		fmt.Printf("-- SHA-256: %s\n", strings.ToUpper(hex.EncodeToString(sha256_cert[:])))
		fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID ) SELECT import_cert(E'\\\\x%s'), 23, 1;\n\n", hex.EncodeToString(cert.Raw))
	}

	fmt.Printf("-- All roots are enabled for Code Signing too.\n")
	fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID ) SELECT rtp.CERTIFICATE_ID, rtp.TRUST_CONTEXT_ID, 4 FROM root_trust_purpose rtp WHERE rtp.TRUST_CONTEXT_ID = 23;\n\n")
	fmt.Printf("COMMIT WORK;\n")
}
