package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TomOnTime/utfutil"

	"go.mozilla.org/pkcs7"
)

type Sequence struct {
	Data asn1.RawValue
}

type CTLEntryValue struct {
	Data []byte
}

type CTLEntryAttribute struct {
	Type  asn1.ObjectIdentifier
	Value CTLEntryValue `asn1:"set"`
}

type CTLEntry struct {
	CertFingerprint []byte
	Attributes      []CTLEntryAttribute `asn1:"set"`
}

type CTL struct {
	Signers         []asn1.ObjectIdentifier
	SequenceNumber  *big.Int
	EffectiveDate   time.Time
	DigestAlgorithm pkix.AlgorithmIdentifier
	Entries         []CTLEntry
	Extensions      []pkix.Extension `asn1:"omitempty,optional,explicit,tag:0"`
}

func OIDList(data []byte) []asn1.ObjectIdentifier {
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(data, &oids); err != nil {
		panic(err)
	}
	return oids
}

type PolicyQualifier struct {
	OID  asn1.ObjectIdentifier
	Bits asn1.BitString
}

type CertPolicy struct {
	OID       asn1.ObjectIdentifier
	Qualifier []PolicyQualifier
}

type CertPolicies struct {
	Policies []CertPolicy
}

func policyList(data []byte) []CertPolicy {
	// Wrap policy list in a SEQUENCE.
	seq := Sequence{Data: asn1.RawValue{FullBytes: data}}
	var der_pol []byte
	var err error
	if der_pol, err = asn1.Marshal(seq); err != nil {
		panic(err)
	}

	var policies CertPolicies
	if _, err = asn1.Unmarshal(der_pol, &policies); err != nil {
		panic(err)
	}

	return policies.Policies
}

func msFiletime(data []byte) *time.Time {
	switch len(data) {
	case 8:
		filetime := time.Date(1601, time.January, 1, 0, 0, int(binary.LittleEndian.Uint64(data)/10000000), 0, time.UTC)
		return &filetime
	case 0:
		return nil // Since forever.
	default:
		panic(fmt.Errorf("unexpected length: %d", len(data)))
	}
}

func utf16to8(data []byte) string {
	if bytes, err := io.ReadAll(utfutil.BytesReader(data, utfutil.WINDOWS)); err != nil {
		panic(err)
	} else {
		return string(bytes[0 : len(bytes)-1])
	}
}

func ctLogList(data []byte) []any {
	var sequences []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &sequences); err != nil {
		panic(err)
	}

	var sequenceOfIntegers []int
	if _, err := asn1.Unmarshal(sequences[0].FullBytes, &sequenceOfIntegers); err != nil {
		panic(err)
	} else {
		fmt.Printf("\n  -- CT Log List Version?: %v\n", sequenceOfIntegers)
	}

	var publicKeys []any
	for _, sequence := range sequences[1:] {
		if pub, err := x509.ParsePKIXPublicKey(sequence.FullBytes); err != nil {
			panic(err)
		} else {
			publicKeys = append(publicKeys, pub)
		}
	}

	return publicKeys
}

func main() {
	// Read DER-encoded authroot PKCS#7 file.
	var err error
	var authroot_data []byte
	if authroot_data, err = os.ReadFile(os.Args[1]); err != nil {
		panic(err)
	}

	// Parse the PKCS#7, whose Content is assumed to have type szOID_CTL (1.3.6.1.4.1.311.10.1).
	var p7 *pkcs7.PKCS7
	if p7, err = pkcs7.Parse(authroot_data); err != nil {
		panic(err)
	}

	// Wrap p7.Content in a SEQUENCE.
	seq := Sequence{Data: asn1.RawValue{FullBytes: p7.Content}}
	var der_ctl []byte
	if der_ctl, err = asn1.Marshal(seq); err != nil {
		panic(err)
	}

	// Parse the CTL.
	var ctl CTL
	if _, err = asn1.Unmarshal(der_ctl, &ctl); err != nil {
		panic(err)
	}

	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 1 AND TRUST_PURPOSE_ID != 50;\n")

	for _, entry := range ctl.Entries {
		var ekus []asn1.ObjectIdentifier
		friendly_name := ""
		var policies []CertPolicy
		cert_sha256 := ""
		var disabled_from *time.Time
		var disabled_ekus []asn1.ObjectIdentifier
		var notbefore_before *time.Time
		var notbefore_ekus []asn1.ObjectIdentifier
		for _, attribute := range entry.Attributes {
			switch attribute.Type.String() {
			case "1.3.6.1.4.1.311.10.11.9":
				ekus = OIDList(attribute.Value.Data) // CERT_ENHKEY_USAGE_PROP_ID
			case "1.3.6.1.4.1.311.10.11.11":
				friendly_name = utf16to8(attribute.Value.Data) // CERT_FRIENDLY_NAME_PROP_ID
			case "1.3.6.1.4.1.311.10.11.20": // CERT_KEY_IDENTIFIER_PROP_ID
			case "1.3.6.1.4.1.311.10.11.29": // CERT_SUBJECT_NAME_MD5_HASH_PROP_ID
			case "1.3.6.1.4.1.311.10.11.83":
				policies = policyList(attribute.Value.Data) // CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID
			case "1.3.6.1.4.1.311.10.11.98":
				cert_sha256 = hex.EncodeToString(attribute.Value.Data) // CERT_AUTH_ROOT_SHA256_HASH_PROP_ID
			case "1.3.6.1.4.1.311.10.11.104":
				disabled_from = msFiletime(attribute.Value.Data) // CERT_DISALLOWED_FILETIME_PROP_ID
			case "1.3.6.1.4.1.311.10.11.105": // CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID
			case "1.3.6.1.4.1.311.10.11.122":
				disabled_ekus = OIDList(attribute.Value.Data) // CERT_DISALLOWED_ENHKEY_USAGE
			case "1.3.6.1.4.1.311.10.11.126":
				notbefore_before = msFiletime(attribute.Value.Data)
			case "1.3.6.1.4.1.311.10.11.127":
				notbefore_ekus = OIDList(attribute.Value.Data)
			default:
				panic(fmt.Errorf("unexpected attribute: %s", attribute.Type.String()))
			}
		}

		fmt.Printf("\n-- %s [%s]\n", friendly_name, strings.ToUpper(hex.EncodeToString(entry.CertFingerprint)))

		certURL := fmt.Sprintf("http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/%s.crt", strings.ToUpper(hex.EncodeToString(entry.CertFingerprint)))
		resp, err := http.Get(certURL)
		if err != nil {
			panic(fmt.Errorf("%s: failed to download", certURL))
		}
		defer resp.Body.Close()
		derCert, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(fmt.Errorf("%s: failed to read body", certURL))
		}
		sha1Cert := sha1.Sum(derCert)
		if !bytes.Equal(sha1Cert[:], entry.CertFingerprint) {
			panic(fmt.Errorf("%s: cert does not match expected SHA-1 hash (%v vs %v)", certURL, hex.EncodeToString(sha1Cert[:]), hex.EncodeToString(entry.CertFingerprint)))
		}
		sha256Cert := sha256.Sum256(derCert)
		expectedSHA256Cert, err := hex.DecodeString(cert_sha256)
		if err != nil {
			panic(fmt.Errorf("%s: failed to convert SHA-256 hash", certURL))
		}
		if !bytes.Equal(sha256Cert[:], expectedSHA256Cert) {
			panic(fmt.Errorf("%s: cert does not match expected SHA-256 hash", certURL))
		}
		fmt.Printf("SELECT import_cert(E'\\\\x%s');\n", hex.EncodeToString(derCert))

		if len(ekus) == 0 { // Equivalent to anyExtendedKeyUsage.
			ekus = append(ekus, asn1.ObjectIdentifier{2, 5, 29, 37, 0})
		}
		for _, eku := range ekus {
			disabled_string := "NULL"
			if (disabled_from != nil) && (len(disabled_ekus) == 0) {
				disabled_string = fmt.Sprintf("'%s'::timestamp", disabled_from.Format(time.RFC3339))
			} else {
				for _, disabled_eku := range disabled_ekus {
					if eku.Equal(disabled_eku) {
						if disabled_from != nil {
							disabled_string = fmt.Sprintf("'%s'::timestamp", disabled_from.Format(time.RFC3339))
						} else {
							disabled_string = "'-infinity'::date"
						}
						break
					}
				}
			}

			notbefore_string := "NULL"
			if (notbefore_before != nil) && (len(notbefore_ekus) == 0) {
				notbefore_string = fmt.Sprintf("'%s'::timestamp", notbefore_before.Format(time.RFC3339))
			} else {
				for _, notbefore_eku := range notbefore_ekus {
					if eku.Equal(notbefore_eku) {
						if notbefore_before != nil {
							notbefore_string = fmt.Sprintf("'%s'::timestamp", notbefore_before.Format(time.RFC3339))
						} else {
							notbefore_string = "'-infinity'::date"
						}
						break
					}
				}
			}

			fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID, DISABLED_FROM, NOTBEFORE_UNTIL ) SELECT c.ID, 1, tp.ID, %s, %s FROM certificate c, trust_purpose tp WHERE (digest(c.CERTIFICATE, 'sha256') = E'\\\\x%s') AND (tp.ID <= 12)", disabled_string, notbefore_string, cert_sha256)
			if !eku.Equal(asn1.ObjectIdentifier{2, 5, 29, 37, 0}) {
				fmt.Printf(" AND (tp.PURPOSE_OID = '%s')", eku.String())
			}
			fmt.Printf(";\n")
		}

		if len(policies) > 0 {
			for _, policy := range policies {
				if !policy.OID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 94, 1, 1}) { // 1.3.6.1.4.1.311.94.1.1 = EV disabled.
					fmt.Printf("INSERT INTO root_trust_purpose ( CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID ) SELECT c.ID, 1, tp.ID FROM certificate c, trust_purpose tp WHERE (digest(c.CERTIFICATE, 'sha256') = E'\\\\x%s') AND (tp.PURPOSE_OID = '%s');\n", cert_sha256, policy.OID.String())
				}
			}
		}
	}

	for _, extension := range ctl.Extensions {
		switch extension.Id.String() {
		case "1.3.6.1.4.1.311.10.3.52":
			fmt.Printf("\n-- Clear previous Microsoft CT Log List inclusion status.\n")
			fmt.Printf("UPDATE ct_log SET MICROSOFT_INCLUSION_STATUS = NULL;\n")
			fmt.Printf("\n-- Set current Microsoft CT Log List inclusion status.\n")
			fmt.Printf("UPDATE ct_log SET MICROSOFT_INCLUSION_STATUS = 'Usable' WHERE digest(PUBLIC_KEY, 'sha256') IN (")
			ctLogSPKIs := ctLogList(extension.Value)
			for i, ctLogSPKI := range ctLogSPKIs {
				spki, err := x509.MarshalPKIXPublicKey(ctLogSPKI)
				if err != nil {
					panic(err)
				} else if i > 0 {
					fmt.Printf(",\n")
				}
				switch t := ctLogSPKI.(type) {
				case *ecdsa.PublicKey:
					fmt.Printf("  -- ECDSA %s SPKI: %s\n", t.Curve.Params().Name, hex.EncodeToString(spki))
				case *rsa.PublicKey:
					fmt.Printf("  -- RSA-%d SPKI: %s\n", t.N.BitLen(), hex.EncodeToString(spki))
				default:
					panic(fmt.Errorf("unexpected public key type: %T", t))
				}
				sha256SPKI := sha256.Sum256(spki)
				fmt.Printf("  E'\\\\x%s'", hex.EncodeToString(sha256SPKI[:]))
			}
			fmt.Printf("\n);\n")
		default:
			panic(fmt.Errorf("unexpected extension: %s", extension.Id.String()))
		}
	}
}
