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
	"io"
	"net/http"
	"os"
	"time"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

//WIP

func main() {
	log.InitLog("Debug")
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
	mtc.AddPeer(podMessage.Name)
	for _, server := range podMessage.Servers {
		mtc.AddPeer(server)
	}
	//go client(mtc, "https://127.0.0.1:9443")
	go client(mtc, "https://myapp-default.myos-e621c7d733ece1fad737ff54a8912822-0000.us-south.containers.appdomain.cloud/")

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

func client(mt *certificates.MutualTls, address string) {
	logger := log.Log

	time.Sleep(time.Second)
	client := mt.Client()
	logger.Infof("Initiating client %s", address)

	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", address, nil)
	if err != nil {
		logger.Infof("error creating HTTP request: %v", err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	logger.Infof("Initiating client Host %s", req.Host)
	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		logger.Infof("ERROR sending HTTP request: %v", err)
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
	logger := log.Log
	logger.Infof("Server processing request")

	fmt.Fprintf(w, "Hello little client, happy to serve you today\n")
}

func server(mt *certificates.MutualTls) {
	logger := log.Log
	mux := http.NewServeMux()
	mux.HandleFunc("/", process)

	server := mt.Server(mux, ":9443")
	logger.Infof("initiating server")
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("failed ListenAndServeTLS", err)
	}
}
