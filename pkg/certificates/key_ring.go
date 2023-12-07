/*
Copyright 2021 The Knative Authors

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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type KeyRing struct {
	latestPKey int
	latestCert int
	latestSKey int
	pKeys      map[int][]byte
	certs      map[int][]byte
	sKeys      map[int][]byte
	certPem    *x509.Certificate
	prkPem     *rsa.PrivateKey
	rotUrl     string
	peers      map[string]string
}

func NewKeyRing() *KeyRing {
	keyRing := &KeyRing{
		pKeys:      make(map[int][]byte),
		certs:      make(map[int][]byte),
		sKeys:      make(map[int][]byte),
		peers:      make(map[string]string),
		latestPKey: -1,
		latestSKey: -1,
		latestCert: -1,
	}
	return keyRing
}

func (kr *KeyRing) AddPrivateKey(subname string, privateKey []byte) error {
	subname = strings.TrimPrefix(subname, ".")
	current, err := strconv.Atoi(subname)
	if err != nil {
		return fmt.Errorf("cant convert to integer %w", err)
	}
	if kr.latestPKey == current {
		return fmt.Errorf("is a duplicate")
	}
	return kr.AddPrivateKeyAt(current, privateKey)
}

func (kr *KeyRing) AppendPrivateKey(privateKey []byte) error {
	return kr.AddPrivateKeyAt(kr.latestPKey+1, privateKey)
}

func (kr *KeyRing) AddPrivateKeyAt(current int, privateKey []byte) error {
	if len(privateKey) < 16 {
		return fmt.Errorf("ilegal privateKey bytes")
	}
	pkBlock, _ := pem.Decode(privateKey)
	if pkBlock == nil {
		return fmt.Errorf("decoding the private key block returned nil")
	}
	if pkBlock.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("bad pem block, expecting type 'RSA PRIVATE KEY', found %q", pkBlock.Type)
	}
	_, err := x509.ParsePKCS1PrivateKey(pkBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	kr.pKeys[current] = privateKey
	if kr.latestPKey < current {
		kr.latestPKey = current
	}
	return nil
}

func (kr *KeyRing) AddPeer(subname string, servers string) error {
	subname = strings.TrimPrefix(subname, ".")

	kr.peers[subname] = servers
	return nil
}

func (kr *KeyRing) AddSymetricKey(subname string, symenticKey []byte) error {
	subname = strings.TrimPrefix(subname, ".")
	current, err := strconv.Atoi(subname)
	if err != nil {
		return fmt.Errorf("cant convert to integer %w", err)
	}
	if kr.latestSKey == current {
		return fmt.Errorf("is a duplicate")
	}
	return kr.AddSymetricKeyAt(current, symenticKey)
}

func (kr *KeyRing) AppendSymetricKey(symenticKey []byte) error {
	return kr.AddSymetricKeyAt(kr.latestSKey+1, symenticKey)
}

func (kr *KeyRing) SetPeer(client string, servers string) error {
	kr.peers[client] = servers
	return nil
}

func (kr *KeyRing) AddSymetricKeyAt(current int, symenticKey []byte) error {
	if len(symenticKey) < 16 {
		return fmt.Errorf("ilegal symenticKey bytes")
	}

	kr.sKeys[current] = symenticKey
	if kr.latestSKey < current {
		kr.latestSKey = current
	}
	return nil
}

func (kr *KeyRing) AddCert(subname string, cert []byte) error {
	subname = strings.TrimPrefix(subname, ".")
	current, err := strconv.Atoi(subname)
	if err != nil {
		return fmt.Errorf("cant convert to integer %w", err)
	}
	if kr.latestCert == current {
		return fmt.Errorf("is a duplicate")
	}
	return kr.AddCertAt(current, cert)
}

func (kr *KeyRing) AppendCert(cert []byte) error {
	return kr.AddCertAt(kr.latestCert+1, cert)
}

func (kr *KeyRing) SetRotUrl(rotUrl string) error {
	_, err := url.ParseRequestURI(rotUrl)
	if err != nil {
		return fmt.Errorf("Error adding ROT URL %s: %w", rotUrl, err)
	}
	u, err := url.Parse(rotUrl)
	if err != nil {
		return fmt.Errorf("Error adding ROT URL %s: %w", rotUrl, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("ROT URL Scheme must be https")
	}

	_, _, err = net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("Error adding ROT URL %s: %w", rotUrl, err)
	}

	kr.rotUrl = rotUrl
	return nil
}

func (kr *KeyRing) AddCertAt(current int, cert []byte) error {
	if len(cert) < 16 {
		return fmt.Errorf("ilegal cert bytes")
	}
	certBlock, _ := pem.Decode(cert)
	if certBlock == nil {
		return fmt.Errorf("decoding the cert block returned nil")
	}
	if certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("bad cert pem block, expecting type 'CERTIFICATE', found %q", certBlock.Type)
	}
	_, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	kr.certs[current] = cert
	if kr.latestCert < current {
		kr.latestCert = current
	}
	return nil
}

// when adding a cert block use Add(name, pem.EncodeToMemory(cert))
func (kr *KeyRing) Add(name string, item []byte) error {
	var err error
	if strings.HasPrefix(name, CertName) {
		err = kr.AddCert(strings.TrimPrefix(name, CertName), item)
		if err != nil {
			return fmt.Errorf("Error adding cert %s: %w", name, err)
		}
		return nil
	}
	if strings.HasPrefix(name, SymetricKeyName) {
		err = kr.AddSymetricKey(strings.TrimPrefix(name, SymetricKeyName), item)
		if err != nil {
			return fmt.Errorf("Error adding symetricKey %s: %w", name, err)
		}
		return nil
	}
	if strings.HasPrefix(name, PrivateKeyName) {
		err = kr.AddPrivateKey(strings.TrimPrefix(name, PrivateKeyName), item)
		if err != nil {
			return fmt.Errorf("Error adding privateKey %s: %w", name, err)
		}
		return nil
	}
	if name == RotUrlName {
		rotUrl := string(item)
		return kr.SetRotUrl(rotUrl)
	}
	if strings.HasPrefix(name, PeerName) {
		err = kr.AddPeer(strings.TrimPrefix(name, PeerName), string(item))
		if err != nil {
			return fmt.Errorf("Error adding peer for client %s: %w", name, err)
		}
		return nil
	}
	// skip additional unknwon fields
	return nil
}

func (kr *KeyRing) Consolidate() error {
	if kr.rotUrl == "" {
		return fmt.Errorf("missing rotUrl")
	}
	if kr.latestCert < 0 {
		return fmt.Errorf("missing cert")
	}
	if kr.latestPKey < 0 {
		return fmt.Errorf("missing private key")
	}
	if kr.latestSKey < 0 {
		return fmt.Errorf("missing symetric key")
	}

	var err error
	kr.certPem, kr.prkPem, err = parseCert(kr.certs[kr.latestCert], kr.pKeys[kr.latestPKey])
	if err != nil {
		return fmt.Errorf("faield to parse cert: %w", err)
	}

	if !kr.certPem.NotAfter.After(time.Now().Add(rotationThreshold)) {
		return fmt.Errorf("certificate is going to expire %v", kr.certPem.NotAfter)
	}

	return nil
}

func (kr *KeyRing) NumSymetricKeys() int {
	return len(kr.sKeys)
}

func (kr *KeyRing) NumPrivateKeys() int {
	return len(kr.pKeys)
}

func (kr *KeyRing) NumCerts() int {
	return len(kr.certs)
}

func (kr *KeyRing) RotUrl() string {
	return kr.rotUrl
}

func (kr *KeyRing) Peers() map[string]string {
	return kr.peers
}
