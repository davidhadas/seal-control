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
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

func testPod() bool {
	logger := log.Log
	logger.Infof("--------> Starting testPod")

	err := certificates.LoadRotCa()
	if err != nil {
		logger.Infof("Failed to load ROT CA: %v", err)
		return false
	}
	certificates.KubeMgr.DeleteCa("my-workload-name")

	_, err = certificates.CreateNewCA("my-workload-name", "https://127.0.0.1:7443")
	if err != nil {
		logger.Infof("Failed to create a CA: %v", err)
		return false
	}

	_, err = certificates.GetCA("my-workload-name")
	if err != nil {
		logger.Infof("Failed to get a CA: %v", err)
		return false
	}

	pmr := certificates.NewPodMessageReq("my-workload-name", "my-pod")

	podMessage, err := certificates.CreatePodMessage(pmr)
	if err != nil {
		logger.Infof("Failed to CreatePodMessage: %v", err)
		return false
	}
	err = certificates.KubeMgr.DeleteCa("my-workload-name")
	if err != nil {
		logger.Infof("Failed to delete a CA: %v", err)
		return false
	}
	logger.Infof("Done processing secret")
	//certificates.RenewCA(kubeMgr, caKeyRing)
	//certificates.RenewCA(kubeMgr, caKeyRing)
	//certificates.RenewSymetricKey(kubeMgr, caKeyRing)
	cert, caPool, err := certificates.GetTlsFromPodMessage(podMessage)

	mts := &certificates.MutualTls{
		IsServer: true,
		Cert:     cert,
		CaPool:   caPool,
	}
	mts.AddPeer("mypod2")
	mts.AddPeer("my-pod")
	mts.AddPeer("mypod3")

	mtc := &certificates.MutualTls{
		Cert:   cert,
		CaPool: caPool,
	}
	mtc.AddPeer("mypod2")
	mtc.AddPeer("my-pod")
	mtc.AddPeer("mypod3")

	go server(mts, ":7443", handler)
	time.Sleep(time.Second)
	client(mtc)

	certificates.KubeMgr.DeleteCa("my-workload-name")
	return true
}

func client(mt *certificates.MutualTls) {
	client := mt.Client()

	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", "https://127.0.0.1:7443", nil)
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

func handler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "Hello")
}

func server(mt *certificates.MutualTls, address string, handler func(http.ResponseWriter, *http.Request)) {
	logger := log.Log
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	server := mt.Server(mux, address)
	logger.Infoln("Server started")
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Fatal("ListenAndServeTLS", err)
	}
}
