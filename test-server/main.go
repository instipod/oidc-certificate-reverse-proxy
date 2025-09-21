package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// The handler function that will display the client certificate and HTTP header details.
func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "<html><body>")

	// Display client certificate details
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		fmt.Fprintln(w, "<h1>Client Certificate Details</h1>")
		fmt.Fprintln(w, "<ul>")
		fmt.Fprintf(w, "<li><strong>Serial Number:</strong> %s</li>", cert.SerialNumber.String())
		fmt.Fprintf(w, "<li><strong>Subject:</strong> %s</li>", cert.Subject.String())
		fmt.Fprintf(w, "<li><strong>Issuer:</strong> %s</li>", cert.Issuer.String())
		fmt.Fprintf(w, "<li><strong>Not Before:</strong> %s</li>", cert.NotBefore.Format(time.RFC850))
		fmt.Fprintf(w, "<li><strong>Not After:</strong> %s</li>", cert.NotAfter.Format(time.RFC850))
		fmt.Fprintf(w, "<li><strong>Signature Algorithm:</strong> %s</li>", cert.SignatureAlgorithm.String())
		fmt.Fprintf(w, "<li><strong>Public Key Algorithm:</strong> %s</li>", cert.PublicKeyAlgorithm.String())

		// Display Subject Alternative Names (SANs)
		if len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 || len(cert.IPAddresses) > 0 {
			sanList := make([]string, 0)
			if len(cert.DNSNames) > 0 {
				sanList = append(sanList, cert.DNSNames...)
			}
			if len(cert.EmailAddresses) > 0 {
				sanList = append(sanList, cert.EmailAddresses...)
			}
			if len(cert.IPAddresses) > 0 {
				for _, ip := range cert.IPAddresses {
					sanList = append(sanList, ip.String())
				}
			}
			fmt.Fprintf(w, "<li><strong>Subject Alternative Names:</strong> %s</li>", strings.Join(sanList, ", "))
		}

		// Display unknown extensions
		if len(cert.Extensions) > 0 {
			fmt.Fprintln(w, "<li><strong>Extensions:</strong></li>")
			fmt.Fprintln(w, "<ul>")
			for _, ext := range cert.Extensions {
				var oid pkix.Extension
				if _, err := asn1.Unmarshal(ext.Value, &oid); err == nil {
					fmt.Fprintf(w, "<li><strong>OID:</strong> %s, <strong>Critical:</strong> %t, <strong>Value (Base64):</strong> %s</li>",
						oid.Id.String(), oid.Critical, base64.StdEncoding.EncodeToString(oid.Value))
				} else {
					fmt.Fprintf(w, "<li><strong>OID:</strong> %s, <strong>Critical:</strong> %t, <strong>Value (Base64):</strong> %s</li>",
						ext.Id.String(), ext.Critical, base64.StdEncoding.EncodeToString(ext.Value))
				}
			}
			fmt.Fprintln(w, "</ul>")
		}

		// Output certificate as base64 with headers and line breaks
		certBase64 := base64.StdEncoding.EncodeToString(cert.Raw)
		// Add a line break every 64 characters
		var certLines []string
		for i := 0; i < len(certBase64); i += 64 {
			end := i + 64
			if end > len(certBase64) {
				end = len(certBase64)
			}
			certLines = append(certLines, certBase64[i:end])
		}
		certPEM := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----",
			strings.Join(certLines, "\n"))
		fmt.Fprintf(w, "<li><strong>Certificate (Base64):</strong> <pre>%s</pre></li>", certPEM)

		fmt.Fprintln(w, "</ul>")
	} else {
		http.Error(w, "No client certificate provided.", http.StatusForbidden)
		return
	}

	// Display HTTP request headers sorted alphabetically
	fmt.Fprintln(w, "<h1>HTTP Request Headers</h1>")
	fmt.Fprintln(w, "<ul>")

	// Get header names and sort them
	var headerNames []string
	for name := range r.Header {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)

	// Iterate over the sorted names to display headers
	for _, name := range headerNames {
		values := r.Header[name]
		fmt.Fprintf(w, "<li><strong>%s:</strong> %s</li>", name, strings.Join(values, ", "))
	}
	fmt.Fprintln(w, "</ul>")

	fmt.Fprintln(w, "</body></html>")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Error loading server key pair: %v", err)
	}

	clientCAs := x509.NewCertPool()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatalf("Error creating TLS listener: %v", err)
	}

	log.Println("Server started on https://localhost:8443")
	log.Fatal(http.Serve(listener, mux))
}
