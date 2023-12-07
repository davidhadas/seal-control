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
	"net/http"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

// WIP

func main() {
	log.InitLog()
	logger := log.Log
	var err error

	mux := http.NewServeMux()
	mux.HandleFunc("/rot", certificates.Rot_service)

	err = certificates.InitKubeMgr()
	if err != nil {
		logger.Infof("Failed to create a kubeMgr: %v\n", err)
		return
	}
	err = certificates.LoadRotCa()
	if err != nil {
		logger.Infof("Failed to load ROT CA: %v", err)
		return
	}

	cert, caPool, err := certificates.CreateRot(certificates.KubeMgr.RotCaKeyRing)
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %v\n", err)
		return
	}

	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     cert,
		CaPool:   caPool,
	}
	mts.AddPeer("init")
	logger.Infof("Starting rot serices\n")

	server := mts.Server(mux, ":8443")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("ListenAndServeTLS", err)
	}
}
