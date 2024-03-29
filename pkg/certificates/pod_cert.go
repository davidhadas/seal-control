/*
Copyright 2023 David Hadas

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

// Create cert template that we can use on the client/server for TLS
func createTransportCertTemplate(workloadName string, sans []string) (*x509.Certificate, error) {

	cert, err := createCertTemplate(certExpirationInterval, sans)
	if err != nil {
		return nil, err
	}
	var cn string
	if workloadName == "" {
		cn = Organization
	} else {
		cn = workloadName + "." + Organization
	}
	cert.KeyUsage = x509.KeyUsageDigitalSignature
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	cert.Subject = pkix.Name{
		Organization: []string{Organization},
		CommonName:   cn,
	}
	return cert, err
}

// createPodCert generates the certificate for use by client and server
func createPodCert(caKey *rsa.PrivateKey, caCertificate *x509.Certificate, workloadName string, sans ...string) (*pem.Block, *pem.Block, error) {
	// Then create the private key for the serving cert
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random key: %w", err)
	}

	certTemplate, err := createTransportCertTemplate(workloadName, sans)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create the certificate template: %w", err)
	}

	// create a certificate which wraps the public key, sign it with the CA private key
	_, certBlock, err := createCert(certTemplate, caCertificate, &keyPair.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error signing certificate template: %w", err)
	}
	_, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	privateKeyBlock := &pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}
	_, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return privateKeyBlock, certBlock, nil
}

// createPodCert generates the certificate for use by client and server
func createPodCertFromCsr(caKey *rsa.PrivateKey, caCertificate *x509.Certificate, workloadName string, csr []byte) (*pem.Block, error) {
	// Then create the private key for the serving cert
	serialNumber, err := rand.Int(randReader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	clientCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to ParseCertificateRequest: %w", err)
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed to CheckSignature: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certExpirationInterval),
		BasicConstraintsValid: true,
		DNSNames:              clientCSR.DNSNames,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		Subject:               clientCSR.Subject,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// create a certificate which wraps the public key, sign it with the CA private key
	_, certBlock, err := createCert(certTemplate, caCertificate, clientCSR.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("error signing certificate template: %w", err)
	}
	_, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return certBlock, nil
}
