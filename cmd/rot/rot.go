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
	"fmt"
	"net/http"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

const (
	sealCtrlNamespace = "seal-control"
)

// WIP

func main() {
	log.InitLog()
	logger := log.Log
	var err error

	mux := http.NewServeMux()
	mux.HandleFunc("/rot", certificates.Rot_service)

	err = certificates.InitKubeMgr(sealCtrlNamespace)
	if err != nil {
		logger.Infof("Failed to create a kubeMgr: %v\n", err)
		return
	}

	cert, caPool, err := certificates.CreateRot(certificates.KubeMgr.RotCaKeyRing)
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %v\n", err)
		return
	}
	egg, err := certificates.CreateInit(certificates.KubeMgr.RotCaKeyRing, "my-workload", "my-pod", "https://192.168.68.102:8443/rot")
	if err != nil {
		logger.Infof("Failed to CreateInit: %v\n", err)
		return
	}
	eegg, err := egg.Encode()
	if err != nil {
		logger.Infof("Failed to encode egg: %v\n", err)
		return
	}
	fmt.Println(eegg)

	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     cert,
		CaPool:   caPool,
	}
	mts.AddPeer("init")

	server := mts.Server(mux)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("ListenAndServeTLS", err)
	}
}
