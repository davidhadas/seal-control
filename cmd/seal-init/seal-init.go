/*
Copyright 2023 David Hadas

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
	"strings"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

// Abandoned for seal-wrap
// Reinstate if container is no lonegr wrapped

func main() {
	log.InitLog("Debug")
	logger := log.Log

	logger.Infof("Seal init starting")
	eggpath := os.Getenv("KO_DATA_PATH")
	podmessagepath := "/seal/podMessage"
	if eggpath == "" {
		eggpath = "./cmd/seal-init/kodata"
		podmessagepath = "/tmp/podMessage"
	}
	eggpath = filepath.Join(eggpath, "egg.txt")

	eegg, err := os.ReadFile(eggpath)
	if err != nil {
		logger.Fatal(err)
		os.Exit(1)
	}

	hostnames := os.Getenv("HOSTNAMES")
	hsplits := strings.Split(hostnames, ",")
	for _, h := range hsplits {
		logger.Infof("adding hostname %s", h)
		if err := certificates.ValidateHostname(h); err != nil {
			logger.Infof("%v", err)
			return
		}
	}

	podData, err := certificates.Rot_client(string(eegg), hsplits)
	if err != nil {
		logger.Infof("Client fail to get podMassage using egg:", err)
		os.Exit(1)
	}
	jPM, err := json.Marshal(podData)
	if err != nil {
		logger.Infof("Fail to marshal egg:", err)
		os.Exit(1)
	}
	err = os.WriteFile(podmessagepath, jPM, 0644)
	if err != nil {
		logger.Infof("Fail to create a file:", err)
		os.Exit(1)
	}
	logger.Infof("Created %s", podmessagepath)
	wks, current, err := podData.GetWKeysFromPodData()
	if err != nil {
		logger.Infof("Fail to get workload keys:", err)
		os.Exit(1)
	}
	symetricKey := wks[current]
	certificates.UnsealDir("/mnt", "/seal", symetricKey, "sealRef", "", map[string]string{})
	logger.Infof("Seal init terminating")
}
