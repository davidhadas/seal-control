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

	"github.com/davidhadas/seal-control/pkg/protocol"
)

// WIP

func main() {
	client := &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost:     0,
			MaxIdleConns:        0,
			MaxIdleConnsPerHost: 0,
		},
	}
	// Create an HTTP request with custom headers
	req, err := http.NewRequest("GET", "http://127.0.0.1:3333/rot", nil)
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
	fmt.Println(string(body))
	var podMessage protocol.PodMessage
	err = json.Unmarshal(body, &podMessage)
	if err != nil {
		fmt.Println("Failed to unmarshal body:", err)
		return
	}
	// Print the response body
	fmt.Printf("\n\n\n\t%v\n", podMessage)
}
