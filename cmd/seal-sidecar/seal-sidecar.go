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
	"io"
	"net/http"
	"os"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

//WIP

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

	mtc := &certificates.MutualTls{
		Cert:   cert,
		CaPool: caPool,
	}
	mtc.AddPeer("mypod2")
	mtc.AddPeer("my-pod")
	mtc.AddPeer("mypod3")
	go client(mtc)

	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     cert,
		CaPool:   caPool,
	}
	mts.AddPeer("mypod2")
	mts.AddPeer("my-pod")
	mts.AddPeer("mypod3")
	server(mts)
}

func client(mt *certificates.MutualTls) {
	logger := log.Log

	client := mt.Client()
	logger.Infof("Initiating client")

	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", "https://127.0.0.1:8443", nil)
	if err != nil {
		logger.Infof("error creating HTTP request: %v", err)
		return
	}
	req.Header.Add("Content-Type", "application/json")

	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		logger.Infof("error sending HTTP request: %v", err)
		return
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Infof("error reading HTTP response body: %v", err)
		return
	}

	// Print the response body
	fmt.Println(string(body))
}

func process(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "Hello")
}

func server(mt *certificates.MutualTls) {
	logger := log.Log
	mux := http.NewServeMux()
	mux.HandleFunc("/", process)

	server := mt.Server(mux)
	logger.Infof("initiating server")
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("failed ListenAndServeTLS", err)
	}
}
