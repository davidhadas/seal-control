/*
Copyright 2023 The Knative Authors

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

package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type PodMessage struct {
	Name        string         `json:"name"`
	CurrentWKey int            `json:"current"`
	WorkloadKey map[int]string `json:"key"`
	PrivateKey  string         `json:"prk"`
	Cert        string         `json:"cert"`
	Ca          []string       `json:"ca"`
}

func NewPodMessage(name string) *PodMessage {
	return &PodMessage{
		Name:        name,
		WorkloadKey: make(map[int]string, 0),
		Ca:          make([]string, 0),
		CurrentWKey: -1,
	}
}

func (pm *PodMessage) GetWorkloadKey() (map[int][]byte, int, error) {
	WkeyMap := make(map[int][]byte, 1)
	for index, base64WK := range pm.WorkloadKey {
		byteArray, err := base64.StdEncoding.DecodeString(base64WK)
		if err != nil {
			return nil, -1, err
		}
		WkeyMap[index] = byteArray
	}
	return WkeyMap, pm.CurrentWKey, nil
}

func (pm *PodMessage) GetPrivateKey() ([]byte, error) {
	return base64.StdEncoding.DecodeString(pm.PrivateKey)
}

func (pm *PodMessage) GetCert() ([]byte, error) {
	return base64.StdEncoding.DecodeString(pm.Cert)
}

func (pm *PodMessage) GetCas() ([][]byte, error) {
	byteArrays := make([][]byte, 1)
	for _, base64Ca := range pm.Ca {
		byteArray, err := base64.StdEncoding.DecodeString(base64Ca)
		if err != nil {
			return nil, err
		}
		byteArrays = append(byteArrays, byteArray)
	}
	return byteArrays, nil
}

func (pm *PodMessage) SetWorkloadKey(symetricKey []byte, index int, workloadName []byte) error {
	if index < 0 {
		return fmt.Errorf("ilegal index for workloadKey")
	}
	if len(symetricKey) != 32 {
		return fmt.Errorf("ilegal length for workloadKey")
	}
	if len(workloadName) != 32 {
		return fmt.Errorf("ilegal length for workloadKey")
	}
	workloadKey := make([]byte, 32)

	hkdf := hkdf.New(sha256.New, symetricKey, nil, workloadName)
	_, err := io.ReadFull(hkdf, workloadKey)
	if err != nil {
		return fmt.Errorf("error deriving workloadKey: %w", err)
	}

	pm.WorkloadKey[index] = base64.StdEncoding.EncodeToString(workloadKey)
	if pm.CurrentWKey < 0 {
		pm.CurrentWKey = index
	}
	return nil
}

func (pm *PodMessage) SetPrivateKey(privateKey []byte) {
	pm.PrivateKey = base64.StdEncoding.EncodeToString(privateKey)
}

func (pm *PodMessage) SetCert(cert []byte) {
	pm.Cert = base64.StdEncoding.EncodeToString(cert)
}

func (pm *PodMessage) SetCa(ca []byte) {
	pm.Ca = append(pm.Ca, base64.StdEncoding.EncodeToString(ca))
}
