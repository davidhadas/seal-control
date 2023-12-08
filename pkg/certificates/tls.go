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
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/davidhadas/seal-control/pkg/log"
)

type MutualTls struct {
	IsServer bool
	Cert     *tls.Certificate
	CaPool   *x509.CertPool
	Peers    []string
}

func (mt *MutualTls) AddPeer(name string) {
	if !slices.Contains(mt.Peers, name) {
		mt.Peers = append(mt.Peers, name)
	}
}

func (mt *MutualTls) Verify() func(cs tls.ConnectionState) error {
	var me string
	if mt.IsServer {
		me = "Server"
	} else {
		me = "Client"
	}
	return func(cs tls.ConnectionState) error {
		logger := log.Log
		if len(cs.PeerCertificates) == 0 {
			// Should never happen on a server side
			logger.Infof("mTLS %s: Failed to verify connection. Certificate is missing\n", me)
			return fmt.Errorf("mTLS %s: Failed to verify connection. Certificate is missing", me)
		}

		opts := x509.VerifyOptions{
			Roots:   mt.CaPool,
			DNSName: "any",
		}

		_, err := cs.PeerCertificates[0].Verify(opts)
		if err != nil {
			logger.Infof("mTLS %s: Failed to verify - Looking for: valid certifdicate: %v\n", err)
			return fmt.Errorf("mTLS %s: Failed to verify - Looking for: valid certifdicate: %v\n", err)
		}

		names := cs.PeerCertificates[0].DNSNames
		for _, match := range names {
			if slices.Contains(mt.Peers, match) {
				logger.Infof("mTLS %s: peer verified as %s!\n", me, match)
				return nil
			}
		}

		logger.Infof("mTLS %s: Failed to verify - Looking for: %v, but peer names are: %v\n", me, mt.Peers, names)
		return fmt.Errorf("mTLS %s: Failed to verify - Looking for: %v, but peer names are: %v\n", me, mt.Peers, names)
	}
}

func (mt *MutualTls) GetTlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: false,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		// SNI under Route passthrough:
		// Setting ServerName results in an alternative certificate being returned
		// Setting ServerName to an empty string sets it to equal the hostname by go tls client
		ServerName:       "",
		RootCAs:          mt.CaPool,
		ClientCAs:        mt.CaPool,
		Certificates:     []tls.Certificate{*mt.Cert},
		VerifyConnection: mt.Verify(),
	}
}

func client(caPool *x509.CertPool, cert *tls.Certificate, mt *MutualTls) {
	client := mt.Client()
	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", "https://127.0.0.1:8443", nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}
	req.Header.Add("Authorization", "Bearer <token>")
	req.Header.Add("Content-Type", "application/json")

	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading HTTP response body:", err)
		return
	}

	// Print the response body
	fmt.Println(string(body))
}

func (mt *MutualTls) Client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost:     0,
			MaxIdleConns:        0,
			MaxIdleConnsPerHost: 0,
			TLSClientConfig:     mt.GetTlsConfig(),
		},
	}
}

func (mt *MutualTls) Server(mux *http.ServeMux, address string) *http.Server {
	return &http.Server{
		Handler:           mux,
		Addr:              address,
		ReadHeaderTimeout: 2 * time.Second,  // Slowloris attack
		ReadTimeout:       10 * time.Second, // RUDY attack
		TLSConfig:         mt.GetTlsConfig(),
	}
}
