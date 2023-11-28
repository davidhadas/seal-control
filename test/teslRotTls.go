/*
Copyright 2022 The Knative Authors

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

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

func testRot() {
	log.InitLog()
	logger := log.Log

	mux := http.NewServeMux()
	mux.HandleFunc("/rot", certificates.Rot_service)

	err := certificates.InitKubeMgr(sealCtrlNamespace)
	if err != nil {
		logger.Infof("Failed to create a kubeMgr: %v\n", err)
		return
	}
	scert, scaPool, err := certificates.CreateRot(certificates.KubeMgr.RotCaKeyRing)
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %v\n", err)
		return
	}
	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     scert, //rotCaKeyRing.
		CaPool:   scaPool,
	}
	mts.AddPeer("init")

	// client
	egg, err := certificates.CreateInit(certificates.KubeMgr.RotCaKeyRing, "my-test-workload", "init", "https://127.0.0.1:8443/")
	if err != nil {
		logger.Infof("Failed to CreateInit: %v\n", err)
		return
	}
	eegg, err := egg.Encode()
	if err != nil {
		logger.Infof("Failed to encode egg: %v\n", err)
		return
	}
	//fmt.Println(eegg)

	go rot_client(eegg)
	server(mts)
}

func rot_client(eegg string) {
	protocolMessage, err := certificates.Rot_client(eegg)
	if err != nil {
		fmt.Println("Client fail to get podMassage using egg:", err)
		return
	}
	jegg, err := json.Marshal(protocolMessage)
	if err != nil {
		fmt.Println("Fail to marshal podMessage:", err)
		return
	}
	err = os.WriteFile("./podMessage", jegg, 0644)
	if err != nil {
		fmt.Println("Fail to create a file:", err)
		return
	}
	fmt.Println("Created /seal/podMessage")
}
