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
	"net/http"
	"time"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

const (
	sealCtrlNamespace = "seal-control"
	caName            = "seal-ctrl-ca"
)

// WIP
var kubeMgr *certificates.KubeMgr

func main() {
	log.InitLog()
	logger := log.Log
	var err error

	mux := http.NewServeMux()
	mux.HandleFunc("/rot", getRoT)

	kubeMgr, err = certificates.NewKubeMgr(sealCtrlNamespace, caName)
	if err != nil {
		logger.Infof("Failed to create a kubeMgr: %v\n", err)
		return
	}

	server := &http.Server{
		Handler:           mux,
		Addr:              ":3333",
		ReadHeaderTimeout: 2 * time.Second,  // Slowloris attack
		ReadTimeout:       10 * time.Second, // RUDY attack
	}

	err = server.ListenAndServe()
	if err != nil {
		logger.Fatal("ListenAndServe", err)
	}
}

func getRoT(w http.ResponseWriter, r *http.Request) {
	logger := log.Log

	logger.Infof("got /rot request\n")
	caKeyRing, err := certificates.GetCA(kubeMgr)
	if err != nil {
		logger.Infof("Failed to get a CA: %v\n", err)
		return
	}
	podMessage, err := certificates.CreatePodMessage(caKeyRing, "mypod", []byte("myWorkloadName12myWorkloadName12"))
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %v\n", err)
		return
	}

	logger.Infof("Done processing knative-serving-certs secret\n")
	bytes, err := json.Marshal(podMessage)
	w.Write(bytes)
}
