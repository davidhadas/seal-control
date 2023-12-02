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

package certificates

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

type PodMessageReq struct {
	PodName      string // Lower case, Allocated by KMS, Stored in the encrypted init image
	WorkloadName string // Lower case, Allocated by KMS, stored in the encrypted init image
}

func (pmr *PodMessageReq) Encrypt(key []byte) ([]byte, error) {
	jpmr, err := json.Marshal(pmr)
	if err != nil {
		return nil, fmt.Errorf("fail to mareshal: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	// allocate space for ciphered data
	padding := aes.BlockSize - len(jpmr)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext := append(jpmr, padtext...)
	result := make([]byte, len(plaintext)+aes.BlockSize)

	iv := result[:aes.BlockSize]
	ciphertext := result[aes.BlockSize:]
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("fail to create iv: %w", err)
	}

	ecb := cipher.NewCBCEncrypter(block, iv)
	ecb.CryptBlocks(ciphertext, plaintext)

	return result, nil
}

func (pmr *PodMessageReq) Decrypt(key []byte, ciphertext []byte) error {
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	length := len(ciphertext)
	plaintext := make([]byte, length)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("fail to create a cipher: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	padding := plaintext[len(plaintext)-1]
	jpmr := plaintext[:len(plaintext)-int(padding)]

	err = json.Unmarshal(jpmr, pmr)
	if err != nil {
		return fmt.Errorf("fail to unmareshal: %w", err)
	}
	return nil
}

func ValidateWorkloadName(workload string) error {
	l := len(workload)
	if l > 60 || l < 3 {
		return errors.New("Ilegal workload name legth")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9\-]*$`).MatchString(workload) {
		return errors.New(fmt.Sprintf("Ilegal workload characters"))
	}
	return nil
}

func ValidatePodName(podname string) error {
	l := len(podname)
	if l > 63 || l < 3 {
		return errors.New("Ilegal pod name legth")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9\-]*$`).MatchString(podname) {
		return errors.New("Ilegal pod characters")
	}
	return nil
}

func (pmr *PodMessageReq) Validate() error {
	err := ValidateWorkloadName(pmr.WorkloadName)
	if err != nil {
		return err
	}
	err = ValidatePodName(pmr.PodName)
	if err != nil {
		return err
	}
	return nil
}

type PodMessage struct {
	Name        string         `json:"name"`
	Clients     []string       `json:"clients"`
	Servers     []string       `json:"servers"`
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

func (pm *PodMessage) GetClients() []string {
	return pm.Clients
}

func (pm *PodMessage) GetServers() []string {
	return pm.Servers
}

func (pm *PodMessage) SetWorkloadKey(symetricKey []byte, index int) error {
	if index < 0 {
		return fmt.Errorf("ilegal index for workloadKey")
	}
	if len(symetricKey) != 32 {
		return fmt.Errorf("ilegal length for symetricKey")
	}
	workloadKey := make([]byte, 32)

	hkdf := hkdf.New(sha256.New, symetricKey, nil, nil)
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

func (pm *PodMessage) AddClient(client string) {
	pm.Clients = append(pm.Clients, client)
}

func (pm *PodMessage) AddServer(server string) {
	pm.Servers = append(pm.Servers, server)
}

func CreatePodMessage(caKeyRing *KeyRing, pmr *PodMessageReq) (*PodMessage, error) {
	expirationInterval := time.Hour * 24 * 30 // 30 days
	sans := []string{"any", strings.ToLower(pmr.PodName)}

	podMessage := NewPodMessage(pmr.PodName)
	privateKeyBlock, certBlock, err := createPodCert(caKeyRing.prkPem, caKeyRing.certPem, expirationInterval, sans...)
	if err != nil {
		return nil, fmt.Errorf("Cannot create pod cert for pod %s: %w\n", pmr.PodName, err)

	}
	podMessage.SetCa(caKeyRing.certs[caKeyRing.latestCert])
	for index, cert := range caKeyRing.certs {
		if index != caKeyRing.latestCert {
			podMessage.SetCa(cert)
		}
	}
	podMessage.SetCert(pem.EncodeToMemory(certBlock))
	podMessage.SetPrivateKey(pem.EncodeToMemory(privateKeyBlock))
	err = podMessage.SetWorkloadKey(caKeyRing.sKeys[caKeyRing.latestSKey], caKeyRing.latestSKey)
	if err != nil {
		return nil, fmt.Errorf("Cannot set workload key for pod %s: %w\n", pmr.PodName, err)
	}
	for index, cert := range caKeyRing.sKeys {
		if index != caKeyRing.latestSKey {
			if err != nil {
				return nil, fmt.Errorf("Cannot decode string workload key for pod %s: %w\n", pmr.PodName, err)
			}
			err = podMessage.SetWorkloadKey(cert, index)
			if err != nil {
				return nil, fmt.Errorf("Cannot set workload key for pod %s: %w\n", pmr.PodName, err)
			}
		}
	}
	podMessage.AddClient(pmr.PodName)
	podMessage.AddServer(pmr.PodName)
	for client, servers := range caKeyRing.peers {
		serverSlice := strings.Split(servers, ",")
		if client == pmr.PodName {
			for _, server := range serverSlice {
				podMessage.AddServer(server)
			}
		} else {
			for _, server := range serverSlice {
				if server == pmr.PodName {
					podMessage.AddServer(client)
				}
			}
		}
	}
	return podMessage, nil
}

func GetTlsFromPodMessage(podMessage *PodMessage) (*tls.Certificate, *x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	for _, caString := range podMessage.Ca {
		ca, err := base64.StdEncoding.DecodeString(caString)
		if err != nil {
			return nil, nil, fmt.Errorf("cant decode ca: %w", err)
		}
		caCertPool.AppendCertsFromPEM(ca)
	}
	cert, err := base64.StdEncoding.DecodeString(podMessage.Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("cant decode cert: %w", err)
	}
	prk, err := base64.StdEncoding.DecodeString(podMessage.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cant decode privateKey: %w", err)
	}

	certificate, err := tls.X509KeyPair(cert, prk)
	if err != nil {
		return nil, nil, fmt.Errorf("tls.X509KeyPair failed: %w", err)
	}
	return &certificate, caCertPool, nil
}

func GetWKeysFromPodMessage(podMessage *PodMessage) (map[int][]byte, int, error) {
	wks, current, err := podMessage.GetWorkloadKey()
	if err != nil {
		return nil, -1, fmt.Errorf("failed getting workload keys: %w", err)
	}
	return wks, current, nil
}
