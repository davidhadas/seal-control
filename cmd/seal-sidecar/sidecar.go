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
	"io"
	"net/http"

	"github.com/davidhadas/seal-control/pkg/log"
	"github.com/davidhadas/seal-control/pkg/protocol"
)

func main() {
	mtc := &protocol.MutualTls{
		//	Cert:   cert,
		//	CaPool: caPool,
	}
	mtc.AddPeer("mypod2")
	mtc.AddPeer("mypod")
	mtc.AddPeer("mypod3")
	go client(mtc)

	mts := &protocol.MutualTls{
		IsServer: true,
		//	Cert:     cert,
		//	CaPool:   caPool,
	}
	mts.AddPeer("mypod2")
	mts.AddPeer("mypod")
	mts.AddPeer("mypod3")
	server(mts)
}

func client(mt *protocol.MutualTls) {
	client := mt.Client()

	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", "https://127.0.0.1:8443", nil)
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

func server(mt *protocol.MutualTls) {
	logger := log.Log
	mux := http.NewServeMux()
	mux.HandleFunc("/", process)

	server := mt.Server(mux)
	fmt.Printf("Initiating server\n")
	//err := server.ListenAndServeTLS("", "")
	err := server.ListenAndServe()
	if err != nil {
		logger.Fatal("ListenAndServeTLS", err)
	}
}
