package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <security_certificates directory>", os.Args[0])
		return
	}

	certsDir := os.Args[1] + "/certificates"
	evRootConfig, err := os.ReadFile(certsDir + "/evroot.config")
	if err != nil {
		fmt.Fprintf(os.Stderr, "os.ReadFile(evroot.config) => %v\n", err)
		return
	}
	reader := csv.NewReader(strings.NewReader(string(evRootConfig)))
	reader.Comma = ' '
	reader.Comment = '#'
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "reader.ReadAll(evRootConfig) => %v\n", err)
		return
	}

	evMap := make(map[string][]string)
	for _, line := range records {
		oid := line[0]
		for i := 1; i < len(line); i++ {
			evMap[line[i]] = append(evMap[line[i]], oid)
		}
	}

	// buildRootKeychain.rb adds the CABForum EV Policy OID to all roots mentioned in evroot.config.
	for rootFilename, evoids := range evMap {
		needToAddCABFOID := true
		for _, evoid := range evoids {
			if evoid == "2.23.140.1.1" {
				needToAddCABFOID = false
				break
			}
		}
		if needToAddCABFOID {
			evMap[rootFilename] = append(evMap[rootFilename], "2.23.140.1.1")
		}
	}

	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 12;\n")
	rootsDir := certsDir + "/roots"
	if files, err := os.ReadDir(rootsDir); err != nil {
		fmt.Fprintf(os.Stderr, "os.ReadDir(rootsDir) => %v\n", err)
		return
	} else {
		for _, file := range files {
			if file.Name() == "AppleDEVID.cer" || file.Name() == ".cvsignore" { // buildRootKeychain.rb omits AppleDEVID.cer from SystemRootCertificates.keychain.
				fmt.Fprintf(os.Stderr, "AppleDEVID.cer => skipped\n")
			} else if root, err := os.ReadFile(rootsDir + "/" + file.Name()); err != nil {
				fmt.Fprintf(os.Stderr, "os.ReadFile(%s) => %v\n", file.Name(), err)
				return
			} else if cert, err := x509.ParseCertificate(root); err != nil {
				fmt.Fprintf(os.Stderr, "%s => %v\n", file.Name(), err)
				return
			} else {
				fmt.Fprintf(os.Stderr, "%s => processed\n", file.Name())
				fmt.Printf("\n-- %s\n", cert.Subject.String())
				fmt.Printf("SELECT import_cert(E'\\\\x%s');\n", strings.ToUpper(hex.EncodeToString(root)))
				sha256Fingerprint := sha256.Sum256(cert.Raw)
				fmt.Printf("INSERT INTO root_trust_purpose (CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID) SELECT c.ID, 12, tp.ID FROM certificate c, trust_purpose tp WHERE digest(c.CERTIFICATE, 'sha256') = E'\\\\x%s' AND tp.PURPOSE_OID IN ('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.3', '1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.7'", strings.ToUpper(hex.EncodeToString(sha256Fingerprint[:])))
				for _, evoid := range evMap[file.Name()] {
					fmt.Printf(", '%s'", evoid)
				}
				fmt.Printf(");\n")
			}
		}
	}
}
