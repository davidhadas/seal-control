/*
Copyright 2022 David Hadas

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

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

func testRot() bool {
	logger := log.Log
	logger.Infof("--------> Starting testRot")
	mux := http.NewServeMux()
	mux.HandleFunc("/rot", certificates.Rot_service)

	err := certificates.LoadRotCa()
	if err != nil {
		logger.Infof("Failed to load ROT CA: %v", err)
		return false
	}
	scert, scaPool, err := certificates.CreateRotService()
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %v", err)
		return false
	}
	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     scert, //rotCaKeyRing.
		CaPool:   scaPool,
	}
	mts.AddPeer("init")
	certificates.KubeMgr.DeleteCa("my-test-workload")
	_, err = certificates.CreateNewCA("my-test-workload", "https://127.0.0.1:8443")
	if err != nil {
		logger.Infof("Failed to CreateNewCA: %v", err)
		return false
	}
	// client
	egg, err := certificates.CreateInit("my-test-workload", "init")
	if err != nil {
		logger.Infof("Failed to CreateInit: %v", err)
		return false
	}
	eegg, err := egg.Encode()
	if err != nil {
		logger.Infof("Failed to encode egg: %v", err)
		return false
	}

	go server(mts, ":8443", certificates.Rot_service)

	time.Sleep(time.Second)
	ret := rot_client(eegg, []string{"xyz.xyz", "z1.z3"})
	certificates.KubeMgr.DeleteCa("my-test-workload")
	return ret

}

func rot_client(eegg string, hostnames []string) bool {
	protocolMessage, err := certificates.Rot_client(eegg, hostnames)
	if err != nil {
		fmt.Println("Client fail to get podMassage using egg:", err)
		return false
	}
	jegg, err := json.Marshal(protocolMessage)
	if err != nil {
		fmt.Println("Fail to marshal podMessage:", err)
		return false
	}
	err = os.WriteFile("./podMessage", jegg, 0644)
	if err != nil {
		fmt.Println("Fail to create a file:", err)
		return false
	}
	fmt.Println("Created /seal/podMessage")
	return true
}
