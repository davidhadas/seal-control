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

func main() {
	log.InitLog()
	logger := log.Log

	eggpath := os.Getenv("KO_DATA_PATH")
	podmessagepath := "/seal/podMessage"
	if eggpath == "" {
		podmessagepath = "/tmp/podMessage"
	}

	var podMessage certificates.PodMessage
	bytes, err := os.ReadFile(podmessagepath)
	if err != nil {
		logger.Infof("fail to create a file: %v", err)
		return
	}
	err = json.Unmarshal(bytes, &podMessage)
	if err != nil {
		logger.Infof("failed to unmarshal body: %v", err)
		return
	}
	// Print the response body
	logger.Infof("podMessage OK")

	cert, caPool, err := certificates.GetTlsFromPodMessage(&podMessage)

	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     cert,
		CaPool:   caPool,
	}
	mts.AddPeer(podMessage.Name)
	for _, client := range podMessage.Clients {
		mts.AddPeer(client)
	}

	server(mts)
}

func process(w http.ResponseWriter, _ *http.Request) {
	logger := log.Log
	logger.Infof("Server processing request")

	fmt.Fprintf(w, "Hello")
}

func server(mt *certificates.MutualTls) {
	logger := log.Log

	logger.Infof("server with sans: %v", mt.Peers)
	mux := http.NewServeMux()
	mux.HandleFunc("/", process)

	server := mt.Server(mux, ":9443")
	logger.Infof("initiating server")
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("failed ListenAndServeTLS", err)
	}
}
