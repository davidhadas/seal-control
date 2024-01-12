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

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

func testPmr() bool {
	logger := log.Log
	logger.Infof("--------> Starting testPmr")

	pmr, err := certificates.NewPodMessageReq("my-workload", "my-pod")
	if err != nil {
		fmt.Printf("Failed to create PodMessageReq: %v\n", err)
		return false
	}
	err = pmr.Encrypt([]byte("abcdef0123456789"))
	if err != nil {
		logger.Infof("Failed Encrypt PMR: %v", err)
		return false
	}
	err = pmr.Decrypt([]byte("abcdef0123456789"))
	if err != nil {
		logger.Infof("Failed Decrypt PMR:  %v", err)
		return false
	}
	logger.Infof("PMR:  %v", pmr)
	return true
}
