/*
Copyright 2023 The Knative Authors

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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/davidhadas/seal-control/pkg/protocol"
)

// Create cert template that we can use on the client/server for TLS
func createTransportCertTemplate(expirationInterval time.Duration, sans []string) (*x509.Certificate, error) {
	cert, err := createCertTemplate(expirationInterval, sans)
	if err != nil {
		return nil, err
	}
	cert.KeyUsage = x509.KeyUsageDigitalSignature
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	cert.Subject = pkix.Name{
		Organization: []string{Organization},
		CommonName:   "seal-control",
	}
	return cert, err
}

// createPodCert generates the certificate for use by client and server
func createPodCert(caKey *rsa.PrivateKey, caCertificate *x509.Certificate, expirationInterval time.Duration, sans ...string) (*pem.Block, *pem.Block, error) {
	// Then create the private key for the serving cert
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random key: %w", err)
	}

	certTemplate, err := createTransportCertTemplate(expirationInterval, sans)
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

func CreatePodMessage(caKeyRing *KeyRing, name string, workloadName []byte) (*protocol.PodMessage, error) {
	expirationInterval := time.Hour * 24 * 30 // 30 days
	sans := []string{"any", name}

	podMessage := protocol.NewPodMessage(name)
	privateKeyBlock, certBlock, err := createPodCert(caKeyRing.prkPem, caKeyRing.certPem, expirationInterval, sans...)
	if err != nil {
		return nil, fmt.Errorf("Cannot create pod cert for pod %s: %w\n", name, err)

	}
	podMessage.SetCa(caKeyRing.certs[caKeyRing.latestCert])
	for index, cert := range caKeyRing.certs {
		if index != caKeyRing.latestCert {
			podMessage.SetCa(cert)
		}
	}
	podMessage.SetCert(pem.EncodeToMemory(certBlock))
	podMessage.SetPrivateKey(pem.EncodeToMemory(privateKeyBlock))
	err = podMessage.SetWorkloadKey(caKeyRing.sKeys[caKeyRing.latestSKey], caKeyRing.latestSKey, workloadName)
	if err != nil {
		return nil, fmt.Errorf("Cannot set workload key for pod %s: %w\n", name, err)
	}
	for index, cert := range caKeyRing.sKeys {
		if index != caKeyRing.latestSKey {
			err = podMessage.SetWorkloadKey(cert, index, workloadName)
			if err != nil {
				return nil, fmt.Errorf("Cannot set workload key for pod %s: %w\n", name, err)
			}
		}
	}
	return podMessage, nil
}

func GetTlsFromPodMessage(podMessage *protocol.PodMessage) (*tls.Certificate, *x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	for _, caString := range podMessage.Ca {
		ca, err := base64.StdEncoding.DecodeString(caString)
		if err != nil {
			return nil, nil, fmt.Errorf("cant decode ca: %w", err)
		}
		caCertPool.AppendCertsFromPEM(ca)
	}
	cert, err := base64.StdEncoding.DecodeString(podMessage.Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("cant decode cert: %w", err)
	}
	prk, err := base64.StdEncoding.DecodeString(podMessage.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cant decode privateKey: %w", err)
	}

	certificate, err := tls.X509KeyPair(cert, prk)
	if err != nil {
		return nil, nil, fmt.Errorf("tls.X509KeyPair failed: %w", err)
	}
	return &certificate, caCertPool, nil
}

func GetWKeysFromPodMessage(podMessage *protocol.PodMessage) (map[int][]byte, int, error) {
	wks, current, err := podMessage.GetWorkloadKey()
	if err != nil {
		return nil, -1, fmt.Errorf("failed getting workload keys: %w", err)
	}
	return wks, current, nil
}
