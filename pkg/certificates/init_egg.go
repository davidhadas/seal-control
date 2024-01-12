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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type InitEgg struct {
	RotUrl     string   `json:"rot"`
	EncPmr     []byte   `json:"epmr"`
	PrivateKey string   `json:"prk"`
	Cert       string   `json:"cert"`
	Ca         []string `json:"ca"`
}

func NewInitEgg() *InitEgg {
	return &InitEgg{}
}

func (egg *InitEgg) SetTorUrl(url string) {
	egg.RotUrl = url
}

func (egg *InitEgg) AddCa(ca []byte) {
	egg.Ca = append(egg.Ca, base64.StdEncoding.EncodeToString(ca))

}

func (egg *InitEgg) SetPrivateKey(privateKey []byte) {
	egg.PrivateKey = base64.StdEncoding.EncodeToString(privateKey)
}

func (egg *InitEgg) SetEncPmr(symenticKey []byte, workloadName string, serviceName string) error {
	pmr, err := NewPodMessageReq(workloadName, serviceName)
	if err != nil {
		return fmt.Errorf("failed to NewPodMessageReq: %w", err)
	}
	err = pmr.Encrypt(symenticKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt pmr: %w", err)
	}
	egg.EncPmr = pmr.Secret
	return nil
}

func (egg *InitEgg) SetCert(cert []byte) {
	egg.Cert = base64.StdEncoding.EncodeToString(cert)
}

func (egg *InitEgg) Encode() (string, error) {
	jegg, err := json.Marshal(egg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal egg: %w", err)
	}
	return base64.StdEncoding.EncodeToString(jegg), nil
}

func (egg *InitEgg) Decode(eegg string) error {
	jegg, err := base64.StdEncoding.DecodeString(eegg)
	if err != nil {
		return fmt.Errorf("failed to decode base64 of egg: %w", err)
	}
	err = json.Unmarshal(jegg, egg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal egg: %w", err)
	}
	return nil
}

func (egg *InitEgg) GetCert() (*tls.Certificate, error) {
	cert, err := base64.StdEncoding.DecodeString(egg.Cert)
	if err != nil {
		return nil, fmt.Errorf("cant decode cert: %w", err)
	}
	prk, err := base64.StdEncoding.DecodeString(egg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cant decode privateKey: %w", err)
	}

	certificate, err := tls.X509KeyPair(cert, prk)
	if err != nil {
		return nil, fmt.Errorf("tls.X509KeyPair failed: %w", err)
	}
	return &certificate, nil
}

func (egg *InitEgg) GetCaPool() (*x509.CertPool, error) {

	//caCertPool := x509.NewCertPool()
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain SystemCertPool: %w", err)
	}
	for _, caString := range egg.Ca {
		ca, err := base64.StdEncoding.DecodeString(caString)
		if err != nil {
			return nil, fmt.Errorf("cant decode ca: %w", err)
		}
		caCertPool.AppendCertsFromPEM(ca)
	}

	return caCertPool, nil
}
