package main

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type TrustServiceStatusList struct {
	XMLName                  xml.Name `xml:"TrustServiceStatusList"`
	SchemeInformation        SchemeInformation
	TrustServiceProviderList TrustServiceProviderList
}

type SchemeInformation struct {
	SchemeTerritory    string
	PointersToOtherTSL PointersToOtherTSL
	ListIssueDateTime  time.Time
	NextUpdate         NextUpdate
}

type PointersToOtherTSL struct {
	OtherTSLPointer []OtherTSLPointer
}

type OtherTSLPointer struct {
	TSLLocation           string
	AdditionalInformation AdditionalInformation
}

type AdditionalInformation struct {
	OtherInformation OtherInformation
}

type OtherInformation struct {
	TSLType         string
	SchemeTerritory string
	Ns3MimeType     string `xml:"MimeType"`
}

type NextUpdate struct {
	DateTime *time.Time `xml:"dateTime"`
}

type TrustServiceProviderList struct {
	TrustServiceProvider []TrustServiceProvider
}

type TrustServiceProvider struct {
	TSPInformation TSPInformation
	TSPServices    TSPServices
}

type TSPInformation struct {
	TSPName Name
}

type Name struct {
	Name string
}

type TSPServices struct {
	TSPService []TSPService
}

type TSPService struct {
	ServiceInformation ServiceInformation
}

type ServiceInformation struct {
	ServiceTypeIdentifier        string
	ServiceName                  Name
	ServiceDigitalIdentity       ServiceDigitalIdentity
	ServiceStatus                string
	StatusStartingTime           time.Time
	ServiceInformationExtensions ServiceInformationExtensions
}

type ServiceDigitalIdentity struct {
	DigitalId DigitalId
}

type DigitalId struct {
	X509Certificate string
	X509SubjectName string
}

type ServiceInformationExtensions struct {
	Extension []Extension
}

type Extension struct {
	AdditionalServiceInformation AdditionalServiceInformation
}

type AdditionalServiceInformation struct {
	URI string
}

var http_client *http.Client

func init() {
	http_client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func downloadTrustList(tlurl string) (TrustServiceStatusList, error) {
	var body []byte
	var tssl TrustServiceStatusList

	req, err := http.NewRequest("GET", tlurl, nil)
	if err != nil {
		return tssl, fmt.Errorf("%s: Failed to create request [%s]", tlurl, err)
	}

	req.Header.Set("User-Agent", "crt.sh")
	var resp *http.Response
	for i := 0; i < 10; i++ {
		if resp, err = http_client.Do(req); err != nil {
			log.Printf("%s: Failed to send request [%s]", tlurl, err)
		} else if body, err = io.ReadAll(resp.Body); err != nil {
			log.Printf("%s: Failed to read response body [%s]", tlurl, err)
		} else if err = xml.Unmarshal(body, &tssl); err != nil {
			log.Printf("%s: Failed to unmarshal XML [%s]", tlurl, err)
		} else {
			return tssl, nil
		}
	}

	return tssl, err
}

func processTrustList(tl TrustServiceStatusList, tlurl string) error {
	log.Printf("Downloaded %s: %s\n", tl.SchemeInformation.SchemeTerritory, tlurl)
	log.Printf("  - thisUpdate: %v\n", tl.SchemeInformation.ListIssueDateTime)
	log.Printf("  - nextUpdate: %v\n", tl.SchemeInformation.NextUpdate.DateTime)
	log.Printf("  - TSPs:\n")

	for _, tsp := range tl.TrustServiceProviderList.TrustServiceProvider {
		log.Printf("    - %s\n", tsp.TSPInformation.TSPName.Name)
		fmt.Printf("\n-- TSP: %s\n", tsp.TSPInformation.TSPName.Name)

		for _, tsps := range tsp.TSPServices.TSPService {
			log.Printf("      - %s\n", tsps.ServiceInformation.ServiceName.Name)
			log.Printf("        - Service Status: %s\n", tsps.ServiceInformation.ServiceStatus)

			// Check the Service Status.
			switch tsps.ServiceInformation.ServiceStatus {
			case "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted":
			case "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn":
			case "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel":
			case "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel":
			default:
				return fmt.Errorf("Unrecognised Service Status: %s\n", tsps.ServiceInformation.ServiceStatus)
			}

			switch tsps.ServiceInformation.ServiceTypeIdentifier {
			// Process these.
			case "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC":
				// Description: A certificate generation service, not qualified, creating and signing non-qualified public key certificates based on the identity and other attributes verified by the relevant registration services.
				// Requirements: When applicable, this service type shall be further specified through the use of an additionalServiceInformation extension (clause 5.5.9.4) within a Service information extension (clause 5.5.9) by using the appropriate identifiers indicating the nature of the public key certificates for which the status has been granted, i.e. certificates for electronic signatures, certificates for electronic seals, and/or certificates for website authentication (as specified in clause 5.5.9.4).
				// When the certificate validity status information (e.g. CRLs, OCSP responses) related to the certificates issued by the listed "CA/PKC" identified service are not signed by the private key corresponding to the listed public key and when no certificate chain/path exists from the related certificate validity status information services (either CRL issuing entities or OCSP responders) to the listed "CA/PKC" identified service public key, those certificate validity status information services shall be listed separately.
				for _, ext := range tsps.ServiceInformation.ServiceInformationExtensions.Extension {
					switch ext.AdditionalServiceInformation.URI {
					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals":
					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures":
					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication":
					case "http://www.nmhh.hu/tl/ServiceStatus/QualifiedatNationalLevel": // Hungary!
					case "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES": // Hungary!
					case "":
					default:
						log.Fatalf("Unexpected Service Information extension: '%s'", ext.AdditionalServiceInformation.URI)
					}
				}

			case "http://uri.etsi.org/TrstSvc/Svctype/CA/QC":
				// Description: A qualified certificate issuing trust service creating and signing qualified certificates based on the identity and other attributes verified by the relevant registration services, and under which are provided the relevant and related revocation and certificate validity status information services (e.g. CRLs, OCSP responses) in accordance with EU Directive 1999/93/EC [i.3] or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of provision. This may also include generation and/or management of the associated private keys on behalf of the certified entity.
				// Requirements: When the listed service is a "root" certificate generation service issuing certificates to one or more subordinates certificate generation services and from which a certification path can be established down to a certificate generation service issuing end-entity qualified certificates, this service type shall be further identified by using the "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-QC" identifier (described in clause D.4) which is included in the additionalServiceInformation extension (clause 5.5.9.4) within a Service information extension (clause 5.5.9).
				// When applicable, this service type shall be further specified through the use of an additionalServiceInformation extension (clause 5.5.9.4) within a Service information extension (clause 5.5.9) by using the appropriate identifiers indicating the nature of the qualified certificates for which the qualified status has been granted, i.e. qualified certificates for electronic signatures, qualified certificates for electronic seals, and/or qualified certificates for website authentication (as specified in clause 5.5.9.4).
				// When, in accordance with Annex II of Regulation (EU) No 910/2014 [i.10], the above described service includes the management of the electronic signature creation data on behalf of the signatory for qualified electronic signatures as part of the provision of qualified electronic signature creation device, and/or includes the management of the electronic seal creation data on behalf of the seal creator for qualified electronic seals as part of the provision of qualified electronic seal creation device, then the qualified certificates for which the private key resides in such a device shall be further identified and specified through the use of a Qualifications extension (clause 5.5.9.2) within a Service information extension (clause 5.5.9) by using the appropriate criteria and qualifiers (clause 5.5.9.2.3).
				// When the certificate validity status information (e.g. CRLs, OCSP responses) related to the qualified certificates issued by the listed "CA/QC" identified service are not signed by the private key corresponding to the listed public key and when no certificate chain/path exists from the related certificate validity status information services (either CRL issuing entities or OCSP responders) to the listed "CA/QC" identified service public key, those certificate validity status information services shall be listed separately.
				disabledFrom := ""
				for _, ext := range tsps.ServiceInformation.ServiceInformationExtensions.Extension {
					switch ext.AdditionalServiceInformation.URI {
					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals":
					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures":
					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication":
						switch tsps.ServiceInformation.ServiceStatus {
						case "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted":
							disabledFrom = "NULL"
						case "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn":
							disabledFrom = "'" + tsps.ServiceInformation.StatusStartingTime.Format(time.RFC3339) + "'"
						default:
							log.Fatalf("Unexpected Service Status for a QWAC Issuer: %s\n", tsps.ServiceInformation.ServiceStatus)
						}
						if tsps.ServiceInformation.ServiceDigitalIdentity.DigitalId.X509SubjectName != "" {
							fmt.Printf("-- Subject Name: %s\n", tsps.ServiceInformation.ServiceDigitalIdentity.DigitalId.X509SubjectName)
						} else {
							fmt.Printf("-- Service Name: %s\n", tsps.ServiceInformation.ServiceName.Name)
						}
						fmt.Printf("INSERT INTO root_trust_purpose (CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID, DISABLED_FROM) SELECT import_cert(decode('%s', 'base64')), 27, 1000, %s;\n", strings.ReplaceAll(tsps.ServiceInformation.ServiceDigitalIdentity.DigitalId.X509Certificate, "\n", ""), disabledFrom)

					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-QC":
					case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-":
					case "":
					default:
						log.Fatalf("Unexpected Service Information extension: '%s'", ext.AdditionalServiceInformation.URI)
					}
				}

			case "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC":
				// A time-stamping service, not qualified, as part of a service from a trust service provider issuing qualified certificates that issues time-stamp tokens that can be used in the validation process of qualified signatures/seals or advanced signatures/seals supported by qualified certificates to ascertain and extend the signature/seal validity when the qualified certificate is (will be) revoked or expired (will expire).
				// TODO: Process this.

			// Ignore these.
			case "http://uri.etsi.org/TrstSvc/Svctype/ACA",
				// An attribute certificate generation service creating and signing attribute certificates based on the identity and other attributes verified by the relevant registration services.
				"http://uri.etsi.org/TrstSvc/Svctype/AdESGeneration",
				// Description: A not qualified generation service for advanced electronic signatures and/or advanced electronic seals.
				// Requirements: When applicable, this service type shall be further specified through the use of an additionalServiceInformation extension (clause 5.5.9.4) within a Service information extension (clause 5.5.9) by using the appropriate identifiers indicating whether it is provided for electronic signatures and/or for electronic seals (as specified in clause 5.5.9.4).
				"http://uri.etsi.org/TrstSvc/Svctype/Archiv",
				// An Archival service.
				"http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL",
				// A certificate validity status service, not qualified, issuing CRLs.
				"http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
				// A certificate validity status information service issuing Online Certificate Status Protocol (OCSP) signed responses and operating an OCSP-server as part of a service from a (qualified) trust service provider issuing qualified certificates, in accordance with the applicable national legislation in the territory identified by the TL Scheme territory (see clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of provision.
				"http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP",
				// A certificate validity status service, not qualified, issuing Online Certificate Status Protocol (OCSP) signed responses.
				"http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q",
				// A qualified electronic registered mail delivery service providing qualified electronic registered mail deliveries in accordance with the applicable national legislation in the territory identified by the TL Scheme territory (see clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of provision.
				"http://uri.etsi.org/TrstSvc/Svctype/EDS/Q",
				// A qualified electronic delivery service providing qualified electronic deliveries in accordance with the applicable national legislation in the territory identified by the TL Scheme territory (see clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of provision.
				"http://uri.etsi.org/TrstSvc/Svctype/IdV",
				// An Identity verification service.
				"http://uri.etsi.org/TrstSvc/Svctype/IdV/nothavingPKIid",
				// An Identity verification service that cannot be identified by a specific PKI-based public key.
				"http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC",
				// A national root signing CA issuing root-signing or qualified certificates to trust service providers and related certification or trust services that are accredited against a national voluntary accreditation scheme or supervised under national law in accordance with the applicable European legislation.
				// TODO: Maybe process this.
				"http://uri.etsi.org/TrstSvc/Svctype/PSES/Q",
				// Description: A qualified preservation service for qualified electronic signatures and/or qualified electronic seals in accordance with the applicable national legislation in the territory identified by the TL Scheme territory (see clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of provision.
				// Requirements: When applicable, this service type shall be further specified through the use of an additionalServiceInformation extension (clause 5.5.9.4) within a Service information extension (clause 5.5.9) by using the appropriate identifiers indicating whether it is provided for electronic signatures and/or for electronic seals (as specified in clause 5.5.9.4).
				"http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q",
				// Description: A qualified validation service for qualified electronic signatures and/or qualified electronic seals in accordance with the applicable national legislation in the territory identified by the TL Scheme territory (see clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of provision.
				// Requirements: When applicable, this service type shall be further specified through the use of an additionalServiceInformation extension (clause 5.5.9.4) within a Service information extension (clause 5.5.9) by using the appropriate identifiers indicating whether it is provided for electronic signatures and/or for electronic seals (as specified in clause 5.5.9.4).
				"http://uri.etsi.org/TrstSvc/Svctype/RA",
				// A registration service that verifies the identity and, if applicable, any specific attributes of a subject for which a certificate is applied for, and whose results are passed to the relevant certificate generation service.
				"http://uri.etsi.org/TrstSvc/Svctype/RA/nothavingPKIid",
				// A registration service
				//   - that verifies the identity and, if applicable, any specific attributes of a subject for which a certificate is applied for, and whose results are passed to the relevant certificate generation service, and
				//   - that cannot be identified by a specific PKI-based public key.
				"http://uri.etsi.org/TrstSvc/Svctype/SignaturePolicyAuthority",
				// A service responsible for issuing, publishing or maintenance of signature policies.
				"http://uri.etsi.org/TrstSvd/Svctype/TLIssuer",
				// HTTP 404.
				"http://uri.etsi.org/TrstSvc/Svctype/TSA",
				// A time-stamping generation service, not qualified, creating and signing time-stamps tokens.
				"http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
				// A qualified electronic time stamp generation service creating and signing qualified electronic time stamps in accordance with the applicable national legislation in the territory identified by the TL Scheme territory (see clause 5.3.10) or with Regulation (EU) No 910/2014 [i.10] whichever is in force at the time of provision.
				// A time-stamping service, not qualified, as part of a service from a trust service provider that issues time-stamp tokens (TST) that can be used in the validation process of qualified signatures/seals or advanced signatures/seals supported by qualified certificates to ascertain and extend the signature/seal validity when the qualified certificate is (will be) revoked or expired (will expire).
				"http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES",
				// A time-stamping service, not qualified, as part of a service from a trust service provider that issues time-stamp tokens (TST) that can be used in the validation process of qualified signatures/seals or advanced signatures/seals supported by qualified certificates to ascertain and extend the signature/seal validity when the qualified certificate is (will be) revoked or expired (will expire).
				"http://uri.etsi.org/TrstSvc/Svctype/unspecified":
				// Description: A trust service of an unspecified type.
				// Requirements: When the "unspecified" Service type identifier is used, information about the nature and type of the listed service shall be provided in other ways such as through a service level extension (see clauses 5.5.6 or 5.5.9).
			// Unrecognised.
			default:
				log.Fatalf("Unrecognised Service Type: %s", tsps.ServiceInformation.ServiceTypeIdentifier)
			}

			log.Printf("        - Service Type: %s\n", tsps.ServiceInformation.ServiceTypeIdentifier)

			for _, ext := range tsps.ServiceInformation.ServiceInformationExtensions.Extension {
				switch ext.AdditionalServiceInformation.URI {
				case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals":
				case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures":
				case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication":
				case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-QC":
				case "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-":
				case "http://www.nmhh.hu/tl/ServiceStatus/QualifiedatNationalLevel":
				case "":
				default:
					log.Fatalf("Unrecognised Service Information Extension: %s", ext.AdditionalServiceInformation.URI)
				}

				log.Printf("        - Additional: %s\n", ext.AdditionalServiceInformation.URI)
			}
		}
	}

	return nil
}

func main() {
	// Download and parse the EUTL list of lists.
	lotlURL := "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
	lotl, err := downloadTrustList(lotlURL)
	if err != nil {
		log.Fatalf("%s: Failed to download LOTL [%s]", lotlURL, err)
	}

	fmt.Printf("DELETE FROM root_trust_purpose WHERE TRUST_CONTEXT_ID = 27;\n")

	// Download, parse, and process the National TLs.
	for _, tlp := range lotl.SchemeInformation.PointersToOtherTSL.OtherTSLPointer {
		switch tlp.AdditionalInformation.OtherInformation.Ns3MimeType {
		case "application/vnd.etsi.tsl+xml":
			fmt.Printf("\n\n-- COUNTRY: %s\n", tlp.AdditionalInformation.OtherInformation.SchemeTerritory)
			if tl, err := downloadTrustList(tlp.TSLLocation); err != nil {
				log.Fatalf("%s: Failed to download TL [%s]", tlp.TSLLocation, err)
			} else if err = processTrustList(tl, tlp.TSLLocation); err != nil {
				log.Fatalf("%s: Failed to process TL [%s]", tlp.TSLLocation, err)
			}

		case "application/pdf": // Ignore this.

		default:
			log.Fatalf("%s: Unsupported MIME type [%s]", tlp.TSLLocation, tlp.AdditionalInformation.OtherInformation.Ns3MimeType)
		}
	}
}
