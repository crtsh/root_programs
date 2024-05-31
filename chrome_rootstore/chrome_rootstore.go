// A current version of root_store.textproto and root_store.certs can be downloaded from:
//
//	https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT
//	https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.certs?format=TEXT
//
// After being downloaded, these files need to be base64-decoded manually.
//
// The root_store package is prebuilt using protoc and https://chromium.googlesource.com/chromium/src/+/main/net/cert/root_store.proto
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	root_store "github.com/crtsh/root_programs/chrome_rootstore/root_store"

	"google.golang.org/protobuf/encoding/prototext"
)

func main() {
	flag.Parse()

	rootStoreFilename := "root_store.textproto"
	certsFilename := "root_store.certs"

	if len(flag.Args()) > 2 {
		fmt.Printf("Usage: %s [<root_store.textproto file>] [<root_store.certs file>]\n", os.Args[0])
		os.Exit(1)
	}

	if len(flag.Args()) >= 1 {
		rootStoreFilename = flag.Arg(0)
	}

	if len(flag.Args()) >= 2 {
		certsFilename = flag.Arg(1)
	}

	rootStore := &root_store.RootStore{}
	rootStoreData, err := os.ReadFile(rootStoreFilename)
	if err != nil {
		log.Fatalf("Failed to read root_store.textproto file: %s", err)
	} else if err = prototext.Unmarshal(rootStoreData, rootStore); err != nil {
		log.Fatalf("Failed to parse root_store.textproto file: %s", err)
	}

	certsData, err := os.ReadFile(certsFilename)
	if err != nil {
		log.Fatalf("Failed to read root_store.certs file: %s", err)
	}

	certsMap := make(map[string]*x509.Certificate)
	for len(certsData) > 0 {
		var block *pem.Block
		if block, certsData = pem.Decode(certsData); block == nil {
			break
		} else if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(block.Bytes); err == nil {
			certSHA256 := sha256.Sum256(cert.Raw)
			certsMap[hex.EncodeToString(certSHA256[:])] = cert
		}
	}

	// Ensure that this root store update is atomic.
	fmt.Printf("BEGIN WORK;\n\n")
	fmt.Printf("LOCK TABLE root_trust_purpose;\n\n")
	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 6;\n\n")

	for _, ta := range rootStore.GetTrustAnchors() {
		if ta != nil {
			certName := ""
			cm := certsMap[ta.GetSha256Hex()]
			if cm != nil {
				if certName = cm.Subject.CommonName; certName == "" {
					if len(cm.Subject.OrganizationalUnit) > 0 {
						certName = cm.Subject.OrganizationalUnit[0]
					} else if len(cm.Subject.Organization) > 0 {
						certName = cm.Subject.Organization[0]
					}
				}
			}
			fmt.Printf("-- %s [%s]\n", certName, ta.GetSha256Hex())
			if cm != nil {
				fmt.Printf("SELECT import_cert(E'\\\\x%s');\n", hex.EncodeToString(cm.Raw))
			}

			notBeforeUntil := "NULL"
			if constraints := ta.GetConstraints(); constraints != nil {
				for _, c := range constraints {
					if sctNotAfterSec := c.GetSctNotAfterSec(); sctNotAfterSec > 0 {
						notBeforeUntil = "'" + time.Unix(sctNotAfterSec, 0).UTC().Format(time.RFC3339) + "'"
					}
				}
			}

			fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID, NOTBEFORE_UNTIL ) SELECT c.ID, 6, 1, %s FROM certificate c WHERE (digest(c.CERTIFICATE, 'sha256') = E'\\\\x%s');\n", notBeforeUntil, ta.GetSha256Hex())
			for _, evPolicy := range ta.GetEvPolicyOids() {
				fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID, NOTBEFORE_UNTIL ) SELECT c.ID, 6, tp.ID, %s FROM certificate c, trust_purpose tp WHERE (digest(c.CERTIFICATE, 'sha256') = E'\\\\x%s') AND (tp.PURPOSE_OID = '%s');\n", notBeforeUntil, ta.GetSha256Hex(), evPolicy)
			}
			fmt.Printf("\n")
		}
	}

	fmt.Printf("COMMIT WORK;\n")
}
