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
	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

func main() {
	log.InitLog("Debug")
	logger := log.Log

	err := certificates.InitRotKubeMgr()
	if err != nil {
		logger.Infof("Failed to create a kubeMgr: %v", err)
		return
	}

	if !testPod() {
		logger.Infof("FAIL!!!")
		return
	}
	if !testPmr() {
		logger.Infof("FAIL!!!")
		return
	}

	if !testRot() {
		logger.Infof("FAIL!!!")
		return
	}

	if !testDataEnc() {
		logger.Infof("FAIL!!!")
		return
	}

	logger.Infof("SUCESS!!!")

}
