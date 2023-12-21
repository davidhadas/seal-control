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
	"encoding/json"
	"fmt"
	"hash/adler32"
	"strings"
)

const sealedPrefixString = "/SEALED/"

var sealedPrefixBytes = []byte{253, 33, 0, 44, 64, 255}

type SealDataMap struct {
	UnsealedMap map[string][]byte
	SealedMap   map[string][]byte
}

func NewSealData() *SealDataMap {
	return &SealDataMap{
		UnsealedMap: make(map[string][]byte),
		SealedMap:   make(map[string][]byte),
	}
}

func (sd *SealDataMap) AddUnsealed(key string, val []byte) {
	sd.UnsealedMap[key] = val
}

func (sd *SealDataMap) AddSealed(key string, val []byte) {
	sd.SealedMap[key] = val
}

func isSealedString(str string) bool {
	return strings.HasPrefix(str, sealedPrefixString)
}

func isSealed(slice []byte) bool {
	for i, b := range slice {
		if i == len(sealedPrefixBytes) {
			return true
		}
		if b != sealedPrefixBytes[i] {
			return false
		}
	}
	return false
}

// EncryptItem() Seals a single item
// key        - a 16 byte key
// reference  - string identifying the full context of this value
// unsealed   - the text to seal
// Note
// EncryptItem may be destructive to the array behind sealedtext
// If needed, use sealedtext := append([]T(nil), sealedtext...) to create a new array
// priot to calling EncryptItem
func (sd *SealDataMap) EncryptItem(key []byte, reference string, unsealed []byte) (sealed []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("key error : %w", err)
	}
	ref := adler32.New()
	ref.Write([]byte(reference))
	unsealed = ref.Sum(unsealed)
	// allocate space for ciphered data
	padding := aes.BlockSize - len(unsealed)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext := append(unsealed, padtext...)
	sealed = make([]byte, len(plaintext)+aes.BlockSize+len(sealedPrefixBytes))

	for i, b := range sealedPrefixBytes {
		sealed[i] = b
	}

	iv := sealed[len(sealedPrefixBytes) : aes.BlockSize+len(sealedPrefixBytes)]
	ciphertext := sealed[aes.BlockSize+len(sealedPrefixBytes):]
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("fail to create iv: %w", err)
	}
	ecb := cipher.NewCBCEncrypter(block, iv)
	ecb.CryptBlocks(ciphertext, plaintext)

	return sealed, nil
	//enc := base64.StdEncoding
	//sealedbytes := make([]byte, enc.EncodedLen(len(sealed)))
	//enc.Encode(sealedbytes, sealed)
	//return string(sealedbytes), nil
}

// DecryptItem() Unseal a single item
// key        - a 16 byte key
// reference  - string identifying teh full context of this value
// sealedtext - the text to unseal
func (sd SealDataMap) DecryptItem(key []byte, reference string, sealed []byte) (unsealed []byte, err error) {
	if !isSealed(sealed) {
		return nil, fmt.Errorf("Not Sealed")
	}
	sealed = sealed[len(sealedPrefixBytes):]

	if len(sealed) < 2*aes.BlockSize {
		return nil, fmt.Errorf("Sealed data seems empty or corrupted")
	}
	iv := sealed[:aes.BlockSize]
	ciphertext := sealed[aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("fail to create a cipher: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	l_plaintext := len(plaintext)
	padding := plaintext[l_plaintext-1]
	checksum := plaintext[l_plaintext-int(padding)-4 : l_plaintext-int(padding)]
	unsealed = plaintext[:l_plaintext-int(padding)-4]

	ref := adler32.New()
	ref.Write([]byte(reference))
	ref_checksum := ref.Sum(nil)
	if !bytes.Equal(checksum, ref_checksum) {
		return nil, fmt.Errorf("checksum failed - wrong reference %s", reference)
	}

	return unsealed, nil
}

func (sd *SealDataMap) Encrypt(key []byte, reference string) (sealed []byte, err error) {
	unsealed, err := json.Marshal(sd.UnsealedMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %w", err)
	}

	sealed, err = sd.EncryptItem(key, reference, unsealed)
	if err != nil {
		return nil, fmt.Errorf("EncryptItem error : %w", err)
	}

	return sealed, nil
}

func (sd *SealDataMap) EncryptItems(key []byte, reference string) error {
	for k, v := range sd.UnsealedMap {
		sealedtext, err := sd.EncryptItem(key, reference, v)
		if err != nil {
			return fmt.Errorf("EncryptItem error : %w", err)
		}
		sd.SealedMap[k] = sealedtext
	}
	return nil
}

/*
	func (sd SealDataMap) DecryptItems(key []byte, reference string) error {
		for k, sealed := range sd.SealedMap {
			unsealed, err := sd.DecryptItem(key, reference, sealed)
			if err != nil {
				//	sd.AddUnsealed(k, []byte(sealedtext))
				fmt.Printf("Fail to DecryptItem %s - %v", k, err)
				continue
				//return fmt.Errorf("fail to DecryptItem %s: %w", k, err)
			}
			sd.AddUnsealed(k, unsealed)
		}
		return nil
	}
*/
func (sd SealDataMap) Decrypt(key []byte, reference string, sealedtext []byte) error {

	unsealed, err := sd.DecryptItem(key, reference, sealedtext)
	if err != nil {
		return fmt.Errorf("fail to Decrypt: %w", err)
	}
	err = json.Unmarshal(unsealed, &sd.UnsealedMap)
	if err != nil {
		return fmt.Errorf("fail to unmarshal: %w", err)
	}
	return nil
}
