package main

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	kSecValidInfoComplete          = 0x00000001
	kSecValidInfoCheckOCSP         = 0x00000002
	kSecValidInfoKnownOnly         = 0x00000004
	kSecValidInfoRequireCT         = 0x00000008
	kSecValidInfoAllowlist         = 0x00000010
	kSecValidInfoNoCACheck         = 0x00000020
	kSecValidInfoOverridable       = 0x00000040
	kSecValidInfoDateConstraints   = 0x00000080
	kSecValidInfoNameConstraints   = 0x00000100
	kSecValidInfoPolicyConstraints = 0x00000200
	kSecValidInfoNoCAV2Check       = 0x00000400

	ekuServerAuth      = "1.3.6.1.5.5.7.3.1"
	ekuClientAuth      = "1.3.6.1.5.5.7.3.2"
	ekuEmailProtection = "1.3.6.1.5.5.7.3.4"
	ekuCodeSigning     = "1.3.6.1.5.5.7.3.3"
	ekuTimeStamping    = "1.3.6.1.5.5.7.3.8"
)

var (
	defaultTrustBitOIDList = []string{ekuServerAuth, ekuClientAuth, ekuEmailProtection, ekuCodeSigning, ekuTimeStamping}
)

// Documentation for the "Valid" DB schema: https://github.com/apple-oss-distributions/Security/blob/main/trust/trustd/SecRevocationDb.c#L1529

func isPlatformRoot(sha256Fingerprint [sha256.Size]byte) bool {
	switch strings.ToUpper(hex.EncodeToString(sha256Fingerprint[:])) {
	case "B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A11001F024": // Apple Root CA
	case "C2B9B042DD57830E7D117DAC55AC8AE19407D38E41D88F3215BC3A890444A050": // Apple Root CA - G2
	case "63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179": // Apple Root CA - G3
	case "0D83B611B648A1A75EB8558400795375CAD92E264ED8E9D7A757C1F5EE2BB22D": // Apple Root Certificate Authority
	case "7AFC9D01A62F03A2DE9637936D4AFE68090D2DE18D03F29C88CFB0B1BA63587F": // Developer ID Certification Authority
	default:
		return false
	}
	return true
}

func groupsFlagsToString(flags int64) string {
	// flags (integer): a bitmask of the following values:
	var flagsString string
	if flags&kSecValidInfoComplete != 0 {
		flagsString += ",kSecValidInfoComplete"
	}
	if flags&kSecValidInfoCheckOCSP != 0 {
		flagsString += ",kSecValidInfoCheckOCSP"
	}
	if flags&kSecValidInfoKnownOnly != 0 {
		flagsString += ",kSecValidInfoKnownOnly"
	}
	if flags&kSecValidInfoRequireCT != 0 {
		flagsString += ",kSecValidInfoRequireCT"
	}
	if flags&kSecValidInfoAllowlist != 0 {
		flagsString += ",kSecValidInfoAllowlist"
	}
	if flags&kSecValidInfoNoCACheck != 0 {
		flagsString += ",kSecValidInfoNoCACheck"
	}
	if flags&kSecValidInfoOverridable != 0 {
		flagsString += ",kSecValidInfoOverridable"
	}
	if flags&kSecValidInfoDateConstraints != 0 {
		flagsString += ",kSecValidInfoDateConstraints"
	}
	if flags&kSecValidInfoNameConstraints != 0 {
		flagsString += ",kSecValidInfoNameConstraints"
	}
	if flags&kSecValidInfoPolicyConstraints != 0 {
		flagsString += ",kSecValidInfoPolicyConstraints"
	}
	if flags&kSecValidInfoNoCAV2Check != 0 {
		flagsString += ",kSecValidInfoNoCAV2Check"
	}

	if flagsString == "" {
		return ""
	} else {
		return flagsString[1:]
	}
}

func groupsPoliciesToOIDListString(flags int64, policies []byte) string {
	// security_certificates (tied to keychain) always enables all trust bits for default-included roots.  More granular trust bits are enforced through 'groups.policies' in the Valid DB.
	//
	// policies (blob): NULL, or uint8_t count value followed by array of int8_t policy values

	if flags&kSecValidInfoPolicyConstraints == 0 {
		if len(policies) == 0 { // NULL indicates that default policy constraints are applied.
			return "'" + strings.Join(defaultTrustBitOIDList, "','") + "'"
		} else {
			log.Fatal("policy constraints flag not set, but policies exist")
		}
	} else if len(policies) == 0 {
		log.Fatal("policy constraints flag set, but no policies exist")
	}

	// Check the uint8_t count value, which indicates the remaining length.
	if int(policies[0]) != len(policies)-1 {
		log.Fatal("unexpected EKU policy length")
	} else if policies[0] == 0 {
		return "" // Empty policy constraints presumably means that all policies are disabled.
	}

	// Parse each int8_t policy value.
	var oidListString string
	for i := 1; i < len(policies); i++ {
		var eku string
		switch policies[i] {
		case 0x01:
			eku = ekuServerAuth
		case 0x02:
			eku = ekuClientAuth
		case 0x03:
			eku = ekuEmailProtection
		case 0x04:
			eku = ekuCodeSigning
		case 0x05:
			eku = ekuTimeStamping
		default:
			log.Fatal("unexpected EKU policy")
		}
		oidListString += ",'" + eku + "'"
	}
	return oidListString[1:]
}

func dateConstraints(flags int64, notAfter sql.NullString) string {
	if flags&kSecValidInfoDateConstraints == 0 {
		if !notAfter.Valid || notAfter.String == "" {
			return "null"
		} else {
			log.Fatal("date constraints flag not set, but dates exist")
		}
	}
	return "'" + notAfter.String + "'::timestamp"
}

func getEVPolicyMap(filename string) map[string][]string {
	// Read EV config file.
	evRootConfig, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	// Parse EV config.
	reader := csv.NewReader(strings.NewReader(string(evRootConfig)))
	reader.Comma = ' '
	reader.Comment = '#'
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	// Create map of EV config.
	evMap := make(map[string][]string)
	for _, line := range records {
		oid := line[0]
		for i := 1; i < len(line); i++ {
			evMap[line[i]] = append(evMap[line[i]], oid)
		}
	}
	// Add the CABForum EV Policy OID to all roots mentioned in evroot.config, mirroring the behaviour of the security_certificates buildRootKeychain.rb script.
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
	return evMap
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <security_certificates directory>", os.Args[0])
		return
	}

	// Parse the EV config file.
	certsDir := os.Args[1] + "/certificates"
	evMap := getEVPolicyMap(certsDir + "/evroot.config")

	// Open the Valid DB snapshot, which contains trust bit restrictions for some roots.
	db, err := sql.Open("sqlite3", os.Args[1]+"/valid_db_snapshot/valid.sqlite3")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Process each files in the "certificates/roots" directory.
	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 12;\n")
	rootsDir := certsDir + "/roots"
	if files, err := os.ReadDir(rootsDir); err != nil {
		fmt.Fprintf(os.Stderr, "os.ReadDir(rootsDir) => %v\n", err)
		return
	} else {
		for _, file := range files {
			if file.Name() == ".cvsignore" {
				continue
			} else if root, err := os.ReadFile(rootsDir + "/" + file.Name()); err != nil {
				fmt.Fprintf(os.Stderr, "os.ReadFile(%s) => %v\n", file.Name(), err)
				return
			} else if cert, err := x509.ParseCertificate(root); err != nil {
				fmt.Fprintf(os.Stderr, "%s => %v\n", file.Name(), err)
				return
			} else {
				// Ignore the "platform roots" that are not considered part of the Apple Root Program despite appearing in security_certificates.
				sha256Fingerprint := sha256.Sum256(cert.Raw)
				if isPlatformRoot(sha256Fingerprint) {
					fmt.Fprintf(os.Stderr, "%s => skipped (platform root)\n", file.Name())
					continue
				}

				fmt.Fprintf(os.Stderr, "%s => processed\n", file.Name())

				fmt.Printf("\n-- %s\n", cert.Subject.String())
				fmt.Printf("SELECT import_cert(E'\\\\x%s');\n", strings.ToUpper(hex.EncodeToString(root)))

				// Fetch any additional trust metadata for this root from the "Valid" DB snapshot.
				var flags, format int64
				var data, policies, sha256 []byte
				var notBefore, notAfter sql.NullString // These are stored on the database as CFAbsoluteTime values (see https://developer.apple.com/documentation/corefoundation/cfabsolutetime).
				err = db.QueryRow(`
SELECT g.FLAGS, g.FORMAT, g.DATA, g.POLICIES, datetime(d.NOTBEFORE, 'unixepoch', '+31 years'), datetime(d.NOTAFTER, 'unixepoch', '+31 years'), h.SHA256
	FROM issuers i
			JOIN groups g ON (i.GROUPID = g.GROUPID)
			LEFT OUTER JOIN dates d ON (i.GROUPID = d.GROUPID)
			LEFT OUTER JOIN hashes h ON (i.GROUPID = h.GROUPID)
	WHERE hex(i.ISSUER_HASH) = ?;
`, strings.ToUpper(hex.EncodeToString(sha256Fingerprint[:]))).Scan(&flags, &format, &data, &policies, &notBefore, &notAfter, &sha256)
				if err != nil && err != sql.ErrNoRows { // If no rows returned, then the default trust bits and constraints apply.
					log.Fatal(err)
				}

				flagsString := groupsFlagsToString(flags)
				trustBitsOIDList := groupsPoliciesToOIDListString(flags, policies)
				notBeforeUntil := dateConstraints(flags, notAfter)

				// TODO: Apply any distrust exemption indicated by the SHA-256 hash from the 'hashes' table.  (e.g., see https://support.apple.com/en-us/103187).

				fmt.Printf("INSERT INTO root_trust_purpose (CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID, NOTBEFORE_UNTIL) SELECT c.ID, 12, tp.ID, %s FROM certificate c, trust_purpose tp WHERE digest(c.CERTIFICATE, 'sha256') = E'\\\\x%s' AND tp.ID != 50 AND tp.PURPOSE_OID IN (%s", notBeforeUntil, strings.ToUpper(hex.EncodeToString(sha256Fingerprint[:])), trustBitsOIDList)
				for _, evoid := range evMap[file.Name()] {
					fmt.Printf(", '%s'", evoid)
				}
				fmt.Printf(");\n")
				if flagsString != "" {
					fmt.Printf("-- Flags: %s\n", flagsString[1:])
				} else {
					fmt.Printf("-- No flags\n")
				}
			}
		}
	}
}
