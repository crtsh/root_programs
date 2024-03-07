package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ca-certificates directory>", os.Args[0])
		return
	}

	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 17;\n")
	rootsDir := os.Args[1] + "/files"
	if files, err := os.ReadDir(rootsDir); err != nil {
		fmt.Fprintf(os.Stderr, "os.ReadDir(rootsDir) => %v\n", err)
		return
	} else {
		for _, file := range files {
			if pemRoot, err := os.ReadFile(rootsDir + "/" + file.Name()); err != nil {
				fmt.Fprintf(os.Stderr, "os.ReadFile(%s) => %v\n", file.Name(), err)
				return
			} else if block, _ := pem.Decode(pemRoot); block == nil || block.Type != "CERTIFICATE" {
				fmt.Fprintf(os.Stderr, "failed to decode PEM certificate")
			} else if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
				fmt.Fprintf(os.Stderr, "%s => %v\n", file.Name(), err)
				return
			} else {
				fmt.Fprintf(os.Stderr, "%s => processed\n", file.Name())
				fmt.Printf("\n-- %s\n", cert.Subject.String())
				fmt.Printf("SELECT import_cert(E'\\\\x%s');\n", strings.ToUpper(hex.EncodeToString(block.Bytes)))
				sha256Fingerprint := sha256.Sum256(cert.Raw)
				fmt.Printf("INSERT INTO root_trust_purpose (CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID) SELECT c.ID, 17, 1 FROM certificate c WHERE digest(c.CERTIFICATE, 'sha256') = E'\\\\x%s';\n", strings.ToUpper(hex.EncodeToString(sha256Fingerprint[:])))
			}
		}
	}
}
