package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/square/certigo/jceks"

	p12 "software.sslmate.com/src/go-pkcs12"
)

func tryJKSKeyStore() []*x509.Certificate {
	// Read and parse cacerts file.
	if keyStore, err := jceks.LoadFromFile(os.Args[1], nil); err != nil {
		return nil
	} else {
		listCerts := keyStore.ListCerts()
		certs := make([]*x509.Certificate, len(listCerts))
		for i, alias := range listCerts {
			if certs[i], err = keyStore.GetCert(alias); err != nil {
				panic(err)
			}
		}
		return certs
	}
}

func tryPasswordlessPKCS12() []*x509.Certificate {
	if p12Data, err := os.ReadFile(os.Args[1]); err != nil {
		return nil
	} else if certs, err := p12.DecodeTrustStore(p12Data, ""); err != nil {
		return nil
	} else {
		return certs
	}
}

func main() {
	// Read cacerts file.  Since https://github.com/openjdk/jdk/pull/5948 the format has been a password-less PKCS#12 file; before then, it was a JKS KeyStore object.
	var certs []*x509.Certificate
	if certs = tryPasswordlessPKCS12(); certs == nil {
		if certs = tryJKSKeyStore(); certs == nil {
			panic(fmt.Errorf("could not parse %s", os.Args[1]))
		}
	}

	// Ensure that this root store update is atomic.
	fmt.Printf("BEGIN WORK;\n\n")
	fmt.Printf("LOCK TABLE root_trust_purpose;\n\n")
	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 23;\n\n")

	// Iterate through the certificates.
	for _, cert := range certs {
		sha256_cert := sha256.Sum256(cert.Raw)
		fmt.Printf("-- %s\n", cert.Subject.String())
		fmt.Printf("-- SHA-256: %s\n", strings.ToUpper(hex.EncodeToString(sha256_cert[:])))
		fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID ) SELECT import_cert(E'\\\\x%s'), 23, 1;\n\n", hex.EncodeToString(cert.Raw))
	}

	fmt.Printf("-- All roots are enabled for Code Signing too.\n")
	fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID ) SELECT rtp.CERTIFICATE_ID, rtp.TRUST_CONTEXT_ID, 4 FROM root_trust_purpose rtp WHERE rtp.TRUST_CONTEXT_ID = 23;\n\n")
	fmt.Printf("COMMIT WORK;\n")
}
