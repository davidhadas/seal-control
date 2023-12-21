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

func testDataEnc() bool {
	logger := log.Log
	logger.Infof("--------> Starting testDataEnc")

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

	workloadCaKeyRing, err := certificates.GetCA("my-workload-name")
	if err != nil {
		logger.Infof("Failed to get a CA: %v", err)
		return false
	}

	sd := certificates.NewSealData()
	secret := []byte("My Secret")
	sealed, err := sd.EncryptItem(workloadCaKeyRing.GetSymetricKey(), "x", secret)
	if err != nil {
		logger.Infof("Failed to EncryptItem: %v", err)
		return false
	}

	unsealed, err := sd.DecryptItem(workloadCaKeyRing.GetSymetricKey(), "x", sealed)
	if err != nil {
		logger.Infof("Failed to DecryptItem: %v", err)
		return false
	}
	if len(secret) != len(unsealed) {
		logger.Infof("Slices are not the same length -  '%s' not same as '%s'", string(secret), string(unsealed))
		return false
	}
	for i, v := range unsealed {
		if v != secret[i] {
			logger.Infof("Slices are not equal, '%s' not same as '%s'", string(secret), string(unsealed))
			return false
		}
	}

	sd.AddUnsealed("testfile", []byte("This is the content of the test file"))
	sd.AddUnsealed("otherfile", []byte("...and this is the content of the other file!"))
	sealed, err = sd.Encrypt(workloadCaKeyRing.GetSymetricKey(), "x")
	if err != nil {
		logger.Infof("Failed to Encrypt: %v", err)
		return false
	}
	sd = certificates.NewSealData()
	err = sd.Decrypt(workloadCaKeyRing.GetSymetricKey(), "x", sealed)
	if err != nil {
		logger.Infof("Failed to Decrypt: %v", err)
		return false
	}
	for k, v := range sd.UnsealedMap {
		logger.Infof("Filename %s content %s", k, v)
	}

	return true
}
