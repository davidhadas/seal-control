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
	"os"
	"path/filepath"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

// WIP

func main() {
	log.InitLog()
	logger := log.Log

	eggpath := os.Getenv("KO_DATA_PATH")
	podmessagepath := "/seal/podMessage"
	if eggpath == "" {
		eggpath = "./kodata"
		podmessagepath = "/tmp/podMessage"
	}
	eggpath = filepath.Join(eggpath, "egg.txt")

	eegg, err := os.ReadFile(eggpath)
	if err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}

	protocolMessage, err := certificates.Rot_client(string(eegg))
	if err != nil {
		logger.Infof("Client fail to get podMassage using egg:", err)
		os.Exit(1)
	}
	jegg, err := json.Marshal(protocolMessage)
	if err != nil {
		logger.Infof("Fail to marshal egg:", err)
		os.Exit(1)
	}
	err = os.WriteFile(podmessagepath, jegg, 0644)
	if err != nil {
		logger.Infof("Fail to create a file:", err)
		os.Exit(1)
	}
	logger.Infof("Created %s", podmessagepath)
}
