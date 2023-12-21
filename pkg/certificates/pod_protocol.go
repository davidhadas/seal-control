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

package certificates

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type PodMessageReqSecret struct {
	ServiceName  string // Lower case, Allocated by KMS, Stored in the encrypted init image
	WorkloadName string // Lower case, Allocated by KMS, stored in the encrypted init image
}

type PodMessageReq struct {
	secret    PodMessageReqSecret // Unencrypted Secret
	Secret    []byte              // Encrypted Secret
	Hostnames []string            // more names requested for the certificate
}

func NewPodMessageReq(workloadName string, serviceName string) *PodMessageReq {
	pmr := &PodMessageReq{}
	pmr.secret.ServiceName = serviceName
	pmr.secret.WorkloadName = workloadName
	return pmr
}

func (pmr *PodMessageReq) Encrypt(key []byte) error {
	jpmr, err := json.Marshal(pmr.secret)
	if err != nil {
		return fmt.Errorf("fail to mareshal: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	// allocate space for ciphered data
	padding := aes.BlockSize - len(jpmr)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext := append(jpmr, padtext...)
	pmr.Secret = make([]byte, len(plaintext)+aes.BlockSize)

	iv := pmr.Secret[:aes.BlockSize]
	ciphertext := pmr.Secret[aes.BlockSize:]
	_, err = rand.Read(iv)
	if err != nil {
		return fmt.Errorf("fail to create iv: %w", err)
	}

	ecb := cipher.NewCBCEncrypter(block, iv)
	ecb.CryptBlocks(ciphertext, plaintext)

	return nil
}

func (pmr *PodMessageReq) Decrypt(key []byte) error {
	if len(pmr.Secret) < 2*aes.BlockSize {
		return fmt.Errorf("Secret seems empty or corrupted")
	}
	iv := pmr.Secret[:aes.BlockSize]
	ciphertext := pmr.Secret[aes.BlockSize:]

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

	err = json.Unmarshal(jpmr, &pmr.secret)
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

func ValidateSevriceName(servicename string) error {
	l := len(servicename)
	if l > 63 || l < 3 {
		return fmt.Errorf("Ilegal service name length: %s", servicename)
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9\-]*$`).MatchString(servicename) {
		return fmt.Errorf("Ilegal pod characters: %s", servicename)
	}
	return nil
}

func ValidateHostname(hostname string) error {
	if hostname != "" {
		if !strings.Contains(hostname, ".") {
			return fmt.Errorf("Ilegal hostname: %s - must structured, e.g. 'myservice.example.com'", hostname)
		}
	}
	return nil
}

func (pmr *PodMessageReq) Validate() error {
	if err := ValidateWorkloadName(pmr.secret.WorkloadName); err != nil {
		return err
	}

	if err := ValidateSevriceName(pmr.secret.ServiceName); err != nil {
		return err
	}

	for _, h := range pmr.Hostnames {
		if err := ValidateHostname(h); err != nil {
			return err
		}
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

func (pm *PodMessage) GetCertPem() (cert []byte, prk []byte, err error) {
	cert, err = base64.StdEncoding.DecodeString(pm.Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("cant decode cert: %w", err)
	}
	prk, err = base64.StdEncoding.DecodeString(pm.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cant decode privateKey: %w", err)
	}
	return
}

func (pm *PodMessage) GetCaPem() ([]byte, error) {
	var caPem []byte
	for _, caString := range pm.Ca {
		ca, err := base64.StdEncoding.DecodeString(caString)
		if err != nil {
			return nil, fmt.Errorf("cant decode ca: %w", err)
		}
		caPem = append(caPem, ca...)
	}
	return caPem, nil
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
	/*
		workloadKey := make([]byte, 32)

		hkdf := hkdf.New(sha256.New, symetricKey, nil, nil)
		_, err := io.ReadFull(hkdf, workloadKey)
		if err != nil {
			return fmt.Errorf("error deriving workloadKey: %w", err)
		}

		pm.WorkloadKey[index] = base64.StdEncoding.EncodeToString(workloadKey)
	*/
	pm.WorkloadKey[index] = base64.StdEncoding.EncodeToString(symetricKey)
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

func CreatePodMessage(pmr *PodMessageReq) (*PodMessage, error) {
	workload := pmr.secret.WorkloadName
	servicename := pmr.secret.ServiceName
	workloadCaKeyRing, err := GetCA(workload)
	if err != nil {
		return nil, fmt.Errorf("Failed to get a CA %s: %v", workload, err)
	}
	//sans := []string{"any", strings.ToLower(pmr.PodName), "myapp-default.myos-e621c7d733ece1fad737ff54a8912822-0000.us-south.containers.appdomain.cloud"}
	sans := []string{"any", strings.ToLower(servicename)}
	for _, hostname := range pmr.Hostnames {
		sans = append(sans, hostname)
	}

	privateKeyBlock, certBlock, err := createPodCert(workloadCaKeyRing.prkPem, workloadCaKeyRing.certPem, workload, sans...)
	if err != nil {
		return nil, fmt.Errorf("Cannot create pod cert for pod %s: %w", servicename, err)
	}
	podMessage := NewPodMessage(servicename)

	podMessage.SetCa(workloadCaKeyRing.certs[workloadCaKeyRing.latestCert])
	for index, cert := range workloadCaKeyRing.certs {
		if index != workloadCaKeyRing.latestCert {
			podMessage.SetCa(cert)
		}
	}
	podMessage.SetCert(pem.EncodeToMemory(certBlock))
	podMessage.SetPrivateKey(pem.EncodeToMemory(privateKeyBlock))
	err = podMessage.SetWorkloadKey(workloadCaKeyRing.sKeys[workloadCaKeyRing.latestSKey], workloadCaKeyRing.latestSKey)
	if err != nil {
		return nil, fmt.Errorf("Cannot set workload key for pod %s: %w", servicename, err)
	}
	for index, cert := range workloadCaKeyRing.sKeys {
		if index != workloadCaKeyRing.latestSKey {
			if err != nil {
				return nil, fmt.Errorf("Cannot decode string workload key for pod %s: %w", servicename, err)
			}
			err = podMessage.SetWorkloadKey(cert, index)
			if err != nil {
				return nil, fmt.Errorf("Cannot set workload key for pod %s: %w", servicename, err)
			}
		}
	}
	podMessage.AddClient(servicename)
	podMessage.AddServer(servicename)
	for client, servers := range workloadCaKeyRing.peers {
		serverSlice := strings.Split(servers, ",")
		if client == servicename {
			for _, server := range serverSlice {
				podMessage.AddServer(server)
			}
		} else {
			for _, server := range serverSlice {
				if server == servicename {
					podMessage.AddServer(client)
				}
			}
		}
	}

	return podMessage, nil
}

func GetTlsFromPodMessage(podMessage *PodMessage) (*tls.Certificate, *x509.CertPool, error) {
	//caCertPool := NewCertPool()
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain SystemCertPool: %w", err)
	}
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
