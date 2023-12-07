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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

func CreateRot(rotKeyRing *KeyRing) (*tls.Certificate, *x509.CertPool, error) {
	expirationInterval := time.Hour * 24 * 30 // 30 days
	sans := []string{"any", "rot", "rot.seal-control"}

	privateKeyBlock, certBlock, err := createPodCert(rotKeyRing.prkPem, rotKeyRing.certPem, expirationInterval, sans...)
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot create pod cert for rot: %w\n", err)

	}
	caArray := [][]byte{rotKeyRing.certs[rotKeyRing.latestCert]}
	for index, cert := range rotKeyRing.certs {
		if index != rotKeyRing.latestCert {
			caArray = append(caArray, cert)
		}
	}
	cert := pem.EncodeToMemory(certBlock)
	prk := pem.EncodeToMemory(privateKeyBlock)

	caCertPool := x509.NewCertPool()
	for _, ca := range caArray {
		caCertPool.AppendCertsFromPEM(ca)
	}

	certificate, err := tls.X509KeyPair(cert, prk)
	if err != nil {
		return nil, nil, fmt.Errorf("tls.X509KeyPair failed: %w", err)
	}
	return &certificate, caCertPool, nil
}

func CreateInit(rotKeyRing *KeyRing, workloadName string, podName string) (*InitEgg, error) {
	initEgg := &InitEgg{
		RotUrl: rotKeyRing.rotUrl,
	}

	expirationInterval := time.Hour * 24 * 30 // 30 days
	sans := []string{"any", "init"}

	privateKeyBlock, certBlock, err := createPodCert(rotKeyRing.prkPem, rotKeyRing.certPem, expirationInterval, sans...)
	if err != nil {
		return nil, fmt.Errorf("Cannot create pod cert for init: %w\n", err)

	}

	initEgg.AddCa(rotKeyRing.certs[rotKeyRing.latestCert])
	for index, cert := range rotKeyRing.certs {
		if index != rotKeyRing.latestCert {
			initEgg.AddCa(cert)
		}
	}
	initEgg.SetCert(pem.EncodeToMemory(certBlock))
	initEgg.SetPrivateKey(pem.EncodeToMemory(privateKeyBlock))
	initEgg.SetEncPmr(rotKeyRing.sKeys[rotKeyRing.latestSKey], workloadName, podName)

	return initEgg, nil
}
