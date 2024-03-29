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

package main

import (
	"fmt"
	"net/http"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func main() {
	log.InitLog("Debug")
	logger := log.Log
	var err error

	mux := http.NewServeMux()
	mux.HandleFunc("/rot", certificates.Rot_service)

	err = certificates.InitRotKubeMgr()
	if err != nil {
		logger.Infof("Failed to create a kubeMgr: %v", err)
		return
	}
	err = certificates.LoadRotCa()
	if err != nil {
		if apierrors.IsNotFound(err) {
			fmt.Printf("Failed to load ROT CA: %v\n", err)
			return
		}
		fmt.Printf("Cant access ROT CA: %v\n", err)
		return
	}

	cert, caPool, err := certificates.CreateRotService()
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %v", err)
		return
	}

	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     cert,
		CaPool:   caPool,
	}
	mts.AddPeer("init")
	logger.Infof("Starting rot serices")

	server := mts.Server(mux, ":8443")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("ListenAndServeTLS", err)
	}
}
