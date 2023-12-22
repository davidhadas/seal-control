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
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/davidhadas/seal-control/pkg/log"
)

func CreateRotService() (*tls.Certificate, *x509.CertPool, error) {
	logger := log.Log

	rotUrl := KubeMgr.RotCaKeyRing.RotUrl()
	u, err := url.Parse(rotUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("parse error adding ROT URL %s: %w", rotUrl, err)
	}
	h, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("splitHostPort error adding ROT URL %s: %w", rotUrl, err)
	}
	sans := []string{"any", "rot", "rot.seal-control", "127.0.0.1", h}

	logger.Infof("Sans: %v\n", sans)

	privateKeyBlock, certBlock, err := createPodCert(KubeMgr.RotCaKeyRing.prkPem, KubeMgr.RotCaKeyRing.certPem, "", sans...)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create pod cert for rot: %w", err)
	}

	caArray := [][]byte{KubeMgr.RotCaKeyRing.certs[KubeMgr.RotCaKeyRing.latestCert]}
	for index, cert := range KubeMgr.RotCaKeyRing.certs {
		if index != KubeMgr.RotCaKeyRing.latestCert {
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

func CreateInit(workloadName string, serviceName string) (*InitEgg, error) {
	initEgg := NewInitEgg()
	initEgg.SetTorUrl(KubeMgr.RotCaKeyRing.rotUrl)

	sans := []string{"any", "init"}

	privateKeyBlock, certBlock, err := createPodCert(KubeMgr.RotCaKeyRing.prkPem, KubeMgr.RotCaKeyRing.certPem, workloadName, sans...)
	if err != nil {
		return nil, fmt.Errorf("cannot create pod cert for init: %w", err)

	}

	initEgg.AddCa(KubeMgr.RotCaKeyRing.certs[KubeMgr.RotCaKeyRing.latestCert])
	for index, cert := range KubeMgr.RotCaKeyRing.certs {
		if index != KubeMgr.RotCaKeyRing.latestCert {
			initEgg.AddCa(cert)
		}
	}
	initEgg.SetCert(pem.EncodeToMemory(certBlock))
	initEgg.SetPrivateKey(pem.EncodeToMemory(privateKeyBlock))
	initEgg.SetEncPmr(KubeMgr.RotCaKeyRing.sKeys[KubeMgr.RotCaKeyRing.latestSKey], workloadName, serviceName)

	return initEgg, nil
}
