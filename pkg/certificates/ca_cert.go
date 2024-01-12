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
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	Organization           = "research.ibm.com"
	CertName               = "tls.crt"
	PrivateKeyName         = "tls.key"
	SymetricKeyName        = "sym.key"
	RotUrlName             = "rot-url"
	rotationThreshold      = 24 * time.Hour
	caExpirationInterval   = time.Hour * 24 * 365 * 10 // 10 years
	certExpirationInterval = time.Hour * 24 * 30       // 30 days
	RotCaName              = "rot-ca"
	PeerName               = "peer"
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
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	return &tmpl, nil
}

// Create cert template suitable for CA and hence signing
func createCACertTemplate(workloadName string) (*x509.Certificate, error) {
	rootCert, err := createCertTemplate(caExpirationInterval, []string{})
	if err != nil {
		return nil, err
	}

	var org string
	if workloadName == "" {
		org = Organization
	} else {
		org = workloadName + "." + Organization
	}
	// Make it into a CA cert and change it so we can use it to sign certs
	rootCert.IsCA = true
	rootCert.KeyUsage = x509.KeyUsageCertSign
	rootCert.Subject = pkix.Name{
		Organization: []string{org},
		CommonName:   "WorkloadCA",
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
			return nil, fmt.Errorf("ilegal secret: %w", err)
		}
	}
	err := keyRing.Consolidate()
	if err != nil {
		return nil, fmt.Errorf("malformed secret: %v", err)
	}
	return keyRing, nil
}

func commitUpdatedCaSecret(secret *corev1.Secret, keys *KeyRing) error {
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

	secret.Data[RotUrlName] = []byte(keys.rotUrl)

	for client, servers := range keys.peers {
		secret.Data[fmt.Sprintf("%s.%s", PeerName, client)] = []byte(servers)
	}

	_, err := KubeMgr.UpdateCA(secret)
	return err
}

// createCACerts generates the root CA cert
func createCACerts(workloadName string, keyRing *KeyRing) error {
	caKeyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("error generating random key: %w", err)
	}

	rootCertTmpl, err := createCACertTemplate(workloadName)
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
	return nil
}

func processWorkloadname(workloadName string) (string, error) {
	if workloadName == RotCaName {
		return "", fmt.Errorf("ilegal workloadName")
	}
	if workloadName == "" {
		return RotCaName, nil
	}
	if len(workloadName) > 60 {
		return "", fmt.Errorf("workloadName too long")
	}
	return "wl-" + workloadName, nil
}

func CANotFound(workloadName string) bool {
	var err error

	// Certificate Authority
	_, err = KubeMgr.GetCa(workloadName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return true
		}
	}
	return false
}

func GetCA(workloadName string) (keyRing *KeyRing, errout error) {
	var err error

	// Certificate Authority
	caSecret, err := KubeMgr.GetCa(workloadName)
	if err != nil {
		return nil, err
	}

	// Check secret validity
	return parseAndValidateCaSecret(caSecret)

}
func CreateNewCA(workloadName string, rotUrl string) (keyRing *KeyRing, errout error) {
	var err error

	// We need to generate a new CA cert, then shortcircuit the reconciler
	keyRing = NewKeyRing()
	err = createCACerts(workloadName, keyRing)
	if err != nil {
		errout = fmt.Errorf("cannot generate the keypair for the secret: %w", err)
		return
	}
	err = keyRing.Add(RotUrlName, []byte(rotUrl))
	if err != nil {
		errout = err
		return
	}
	_, err = KubeMgr.CreateCa(workloadName)
	if err != nil {
		errout = fmt.Errorf("cannot generate secret: %w", err)
		return
	}
	err = createSymentricKey(keyRing)
	if err != nil {
		errout = fmt.Errorf("cannot generate secret: %w", err)
		return
	}
	err = UpdateCA(workloadName, keyRing)
	if err != nil {
		errout = fmt.Errorf("cannot udpate secret: %w", err)
		return
	}
	return
}

func RenewCA(kubeMgr *KubeMgrStruct, workloadName string, keyRing *KeyRing) error {
	var err error

	err = createCACerts(workloadName, keyRing)
	if err != nil {
		return fmt.Errorf("cannot generate the keypair for the secret: %w", err)
	}

	err = UpdateCA(workloadName, keyRing)
	if err != nil {
		return fmt.Errorf("fail to update secret: %w", err)
	}
	return nil
}

func RenewSymetricKey(kubeMgr *KubeMgrStruct, workloadName string, keyRing *KeyRing) error {
	var err error

	err = createSymentricKey(keyRing)
	if err != nil {
		return fmt.Errorf("cannot generate a new symetric key for the secret: %w", err)
	}

	err = UpdateCA(workloadName, keyRing)
	if err != nil {
		return fmt.Errorf("fail to update secret: %w", err)
	}
	return nil
}

func UpdateCA(workloadName string, keyRing *KeyRing) error {
	var err error

	err = keyRing.Consolidate()
	if err != nil {
		return fmt.Errorf("ilegal secret created: %w", err)
	}

	caSecret, err := KubeMgr.GetCa(workloadName)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("secret not found")
	}
	if err != nil {
		return fmt.Errorf("error accessing secret: %w", err)
	}

	err = commitUpdatedCaSecret(caSecret, keyRing)
	if err != nil {
		return fmt.Errorf("failed to commit the keypair for the secret: %w", err)
	}

	_, err = parseAndValidateCaSecret(caSecret)
	if err != nil {
		return fmt.Errorf("failed while validating keypair for secret: %w", err)
	}
	return nil
}
