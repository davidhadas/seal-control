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

	var podMessage certificates.PodMessage
	bytes, err := os.ReadFile("/seal/podMessage")
	if err != nil {
		fmt.Println("Fail to create a file:", err)
		return
	}
	err = json.Unmarshal(bytes, &podMessage)
	if err != nil {
		fmt.Println("Failed to unmarshal body:", err)
		return
	}
	// Print the response body
	fmt.Printf("podMessage OK\n")

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
	client := mt.Client()
	fmt.Printf("Initiating client\n")

	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", "https://127.0.0.1:8443", nil)
	//req, err := http.NewRequest("GET", "http://127.0.0.1:8443", nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}
	req.Header.Add("Authorization", "Bearer <token>")
	req.Header.Add("Content-Type", "application/json")

	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading HTTP response body:", err)
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
	fmt.Printf("Initiating server\n")
	//logger.Info("Initiating server2\n")
	err := server.ListenAndServeTLS("", "")
	//err := server.ListenAndServe()
	if err != nil {
		logger.Fatal("ListenAndServeTLS", err)
	}
}
