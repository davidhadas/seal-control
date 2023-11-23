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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/davidhadas/seal-control/pkg/log"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	Organization         = "research.ibm.com"
	CertName             = "tls.crt"
	PrivateKeyName       = "tls.key"
	SymetricKeyName      = "sym.key"
	rotationThreshold    = 24 * time.Hour
	caExpirationInterval = time.Hour * 24 * 365 * 10 // 10 years
)

var randReader = rand.Reader
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// Create template common to all certificates
func createCertTemplate(expirationInterval time.Duration, sans []string) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(randReader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(expirationInterval),
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}
	return &tmpl, nil
}

// Create cert template suitable for CA and hence signing
func createCACertTemplate(expirationInterval time.Duration) (*x509.Certificate, error) {
	rootCert, err := createCertTemplate(expirationInterval, []string{})
	if err != nil {
		return nil, err
	}
	// Make it into a CA cert and change it so we can use it to sign certs
	rootCert.IsCA = true
	rootCert.KeyUsage = x509.KeyUsageCertSign
	rootCert.Subject = pkix.Name{
		Organization: []string{Organization},
	}
	return rootCert, nil
}

func createCert(template, parent *x509.Certificate, pub, parentPriv interface{}) (cert *x509.Certificate, certPEM *pem.Block, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	certPEM = &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return
}

// parseCert parses a certificate/private key pair from serialized pem blocks
func parseCert(certPemBytes []byte, privateKeyPemBytes []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPemBytes)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("decoding the cert block returned nil")
	}
	if certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("bad pem block, expecting type 'CERTIFICATE', found %q", certBlock.Type)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	pkBlock, _ := pem.Decode(privateKeyPemBytes)
	if pkBlock == nil {
		return nil, nil, fmt.Errorf("decoding the pk block returned nil")
	}
	if pkBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("bad pem block, expecting type 'RSA PRIVATE KEY', found %q", pkBlock.Type)
	}
	pk, err := x509.ParsePKCS1PrivateKey(pkBlock.Bytes)
	return cert, pk, err
}

func parseAndValidateCaSecret(secret *corev1.Secret) (*KeyRing, error) {
	keyRing := NewKeyRing()
	for keyname, value := range secret.Data {
		err := keyRing.Add(keyname, value)
		if err != nil {
			return nil, fmt.Errorf("ilegal secret in parseAndValidateSecret: %w", err)
		}
	}
	err := keyRing.Consolidate()
	if err != nil {
		return nil, fmt.Errorf("ilegal keyRing in parseAndValidateSecret: %v", err)
	}
	return keyRing, nil
}

func commitUpdatedCaSecret(kubeMgr *KubeMgr, secret *corev1.Secret, keys *KeyRing) error {
	secret.Data = make(map[string][]byte, 6)
	for index, symenticKey := range keys.sKeys {
		secret.Data[fmt.Sprintf("%s.%d", SymetricKeyName, index)] = symenticKey
	}

	for index, cert := range keys.certs {
		secret.Data[fmt.Sprintf("%s.%d", CertName, index)] = cert
	}

	for index, privateKey := range keys.pKeys {
		secret.Data[fmt.Sprintf("%s.%d", PrivateKeyName, index)] = privateKey
	}
	secret, err := kubeMgr.UpdateCA(secret)
	return err
}

// createCACerts generates the root CA cert
func createCACerts(keyRing *KeyRing, expirationInterval time.Duration) error {
	caKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating random key: %w", err)
	}

	rootCertTmpl, err := createCACertTemplate(expirationInterval)
	if err != nil {
		return fmt.Errorf("error generating CA cert: %w", err)
	}

	_, caCertBlock, err := createCert(rootCertTmpl, rootCertTmpl, &caKeyPair.PublicKey, caKeyPair)
	if err != nil {
		return fmt.Errorf("error signing the CA cert: %w", err)
	}
	caPrivateKeyBlock := &pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKeyPair),
	}

	keyRing.AppendCert(pem.EncodeToMemory(caCertBlock))
	keyRing.AppendPrivateKey(pem.EncodeToMemory(caPrivateKeyBlock))
	err = keyRing.Consolidate()
	if err != nil {
		return fmt.Errorf("ilegal keyRing in createCACerts: %w", err)
	}
	return nil
}

// createCACerts generates the root CA cert
func createSymentricKey(keyRing *KeyRing) error {
	symentricKey := make([]byte, 32)
	_, err := rand.Read(symentricKey)
	if err != nil {
		return fmt.Errorf("failed to generate symetric key: %w", err)
	}

	keyRing.AppendSymetricKey(symentricKey)
	err = keyRing.Consolidate()
	if err != nil {
		return fmt.Errorf("ilegal keyRing in createCACerts: %w", err)
	}
	return nil
}

func GetCA(kubeMgr *KubeMgr) (keyRing *KeyRing, errout error) {
	logger := log.Log

	var err error

	// Certificate Authority
	caSecret, err := kubeMgr.GetCa()
	if apierrors.IsNotFound(err) {
		logger.Infof("secret is missing - lets create it\n")
		kubeMgr.CreateCa()
	}
	if err != nil {
		errout = fmt.Errorf("Error accessing secret: %w\n", err)
		return
	}
	keyRing, err = parseAndValidateCaSecret(caSecret)
	if err != nil {
		logger.Infof("secret is missing the required keys - lets add it\n")

		// We need to generate a new CA cert, then shortcircuit the reconciler

		keyRing = NewKeyRing()
		err = createCACerts(keyRing, caExpirationInterval)
		if err != nil {
			errout = fmt.Errorf("Cannot generate the keypair for the secret: %w\n", err)
			return
		}

		err = createSymentricKey(keyRing)
		if err != nil {
			errout = fmt.Errorf("Cannot generate the keypair for the secret: %w\n", err)
			return
		}

		err = commitUpdatedCaSecret(kubeMgr, caSecret, keyRing)
		if err != nil {
			errout = fmt.Errorf("Failed to commit the keypair for the secret: %w\n", err)
			return
		}

		keyRing, err = parseAndValidateCaSecret(caSecret)
		if err != nil {
			errout = fmt.Errorf("Failed while validating keypair for secret: %w\n", err)
			return
		}
	}
	logger.Infof("Done processing getCA\n")
	return
}

func RenewCA(kubeMgr *KubeMgr, keyRing *KeyRing) error {
	var err error
	logger := log.Log

	err = createCACerts(keyRing, caExpirationInterval)
	if err != nil {
		return fmt.Errorf("Cannot generate the keypair for the secret: %w\n", err)

	}

	caSecret, err := kubeMgr.GetCa()

	if apierrors.IsNotFound(err) {
		logger.Infof("secret is missing - lets create it\n")
		caSecret, err = kubeMgr.CreateCa()
	}
	if err != nil {
		return fmt.Errorf("Error accessing secret: %w\n", err)
	}

	err = commitUpdatedCaSecret(kubeMgr, caSecret, keyRing)
	if err != nil {
		return fmt.Errorf("Failed to commit the keypair for the secret: %w\n", err)
	}

	keyRing, err = parseAndValidateCaSecret(caSecret)
	if err != nil {
		return fmt.Errorf("Failed while validating keypair for secret: %w\n", err)
	}

	logger.Infof("Done added new ca to secret\n")
	return nil
}

func RenewSymetricKey(kubeMgr *KubeMgr, keyRing *KeyRing) error {
	var err error
	logger := log.Log

	err = createSymentricKey(keyRing)
	if err != nil {
		return fmt.Errorf("Cannot generate a new symetric key for the secret: %w\n", err)
	}

	caSecret, err := kubeMgr.GetCa()

	if apierrors.IsNotFound(err) {
		logger.Infof("secret is missing - lets create it\n")
		caSecret, err = kubeMgr.CreateCa()
	}
	if err != nil {
		return fmt.Errorf("Error accessing secret: %w\n", err)
	}

	err = commitUpdatedCaSecret(kubeMgr, caSecret, keyRing)
	if err != nil {
		return fmt.Errorf("Failed to commit the keypair for the secret: %w\n", err)
	}

	keyRing, err = parseAndValidateCaSecret(caSecret)
	if err != nil {
		return fmt.Errorf("Failed while validating keypair for secret: %w\n", err)
	}

	logger.Infof("Done added new ca to secret\n")
	return nil
}
