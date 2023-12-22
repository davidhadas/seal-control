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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/davidhadas/seal-control/pkg/log"
)

func Rot_client(eegg string, hostnames []string) (*PodMessage, map[string]string, error) {
	logger := log.Log

	e := NewInitEgg()
	err := e.Decode(eegg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decodeegg: %w", err)
	}
	ccert, err := e.GetCert()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get cert from egg: %w", err)
	}
	ccaPool, err := e.GetCaPool()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get cert from egg: %w", err)
	}
	mtc := &MutualTls{
		Cert:   ccert,
		CaPool: ccaPool,
	}
	mtc.AddPeer("rot")

	client := mtc.Client()
	pmr := NewPodMessageReq("", "")
	pmr.Secret = e.EncPmr
	pmr.Hostnames = hostnames
	jpmr, err := json.Marshal(pmr)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshal pod message request: %w", err)
	}
	logger.Infof("Approaching ROT at: %s", e.RotUrl)
	// Create an HTTP request with custom headers
	req, err := http.NewRequest("POST", e.RotUrl, bytes.NewBuffer(jpmr))
	if err != nil {
		return nil, nil, fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")

	// Send the HTTP request
	logger.Debugf("found egg, approching Rot")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error sending HTTP request: %w", err)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading HTTP response body: %w", err)
	}
	var podMessage PodMessage
	err = json.Unmarshal(body, &podMessage)
	if err != nil {
		fmt.Printf("body: %s", string(body))
		return nil, nil, fmt.Errorf("failed to unmarshal body: %w", err)
	}
	return &podMessage, e.Options, nil
}

func Rot_service(w http.ResponseWriter, r *http.Request) {
	logger := log.Log

	logger.Infof("Processing /rot request from %s", r.RemoteAddr)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Infof("Failed to read request body: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var pmr PodMessageReq
	err = json.Unmarshal(body, &pmr)
	if err != nil {
		logger.Infof("Failed to unmarshal request body: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := KubeMgr.RotCaKeyRing.sKeys[KubeMgr.RotCaKeyRing.latestSKey]
	err = pmr.Decrypt(key)
	if err != nil {
		for index, key := range KubeMgr.RotCaKeyRing.sKeys {
			if index == KubeMgr.RotCaKeyRing.latestSKey {
				continue
			}
			err = pmr.Decrypt(key)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		logger.Infof("Failed to decode json request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = pmr.Validate()
	if err != nil {
		logger.Infof("Failed to validate pod message request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	podMessage, err := CreatePodMessage(&pmr)
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %", err)
		return
	}

	logger.Infof("Done processing secret")
	bytes, err := json.Marshal(podMessage)
	if err != nil {
		logger.Infof("failed to marshal pod message: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(bytes)
}
