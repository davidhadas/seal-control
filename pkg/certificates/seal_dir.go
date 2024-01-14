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
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/davidhadas/seal-control/pkg/log"
)

func Unseal(symetricKey []byte, sealRef string, cypher string) (sealedDataMap *SealDataMap, err error) {
	if !isSealedString(cypher) {
		err = fmt.Errorf("not sealed")
		return
	}
	sealed, err := base64.StdEncoding.DecodeString(cypher)
	if err != nil {
		err = fmt.Errorf("failed to decode Base64 - err %v", err)
		return
	}

	sealedDataMap = NewSealData()
	err = sealedDataMap.Decrypt(symetricKey, sealRef, sealed)
	if err != nil {
		err = fmt.Errorf("failed to Decrypt: %w", err)
		sealedDataMap = nil
		return
	}
	return
}

func UnsealConfig(symetricKey []byte, sealRef string, sealConfigStr string) (config map[string]string, err error) {
	var sd *SealDataMap
	sd, err = Unseal(symetricKey, sealRef, sealConfigStr)
	if err != nil {
		return
	}
	config = make(map[string]string)
	for k, v := range sd.UnsealedMap {
		config[k] = string(v)
	}
	return
}

func UnsealArgs(symetricKey []byte, sealRef string, argsIn []string, config map[string]string) (cmd string, args []string, err error) {
	if len(argsIn) != 2 {
		err = fmt.Errorf("wrong number of arguments - should be '<Cyphertext>'")
		return
	}

	sd, err := Unseal(symetricKey, sealRef, argsIn[1])
	if err != nil {
		err = fmt.Errorf("failed to decrypt args: %w", err)
		return
	}

	numArgs := len(sd.UnsealedMap)
	if numArgs < 1 {
		err = fmt.Errorf("failed to find EntryPoint in sealed Args")
		return
	}
	command, ok := sd.UnsealedMap["0"]
	if !ok {
		err = fmt.Errorf("failed to find EntryPoint in location 0 of sealed args")
		return
	}
	argsSplits := make([]string, numArgs-1)
	for i := 1; i < numArgs; i++ {
		val, ok := sd.UnsealedMap[strconv.Itoa(i)]
		if !ok {
			err = fmt.Errorf("wrong args structure")
			return
		}
		argsSplits[i-1] = string(val)
	}
	cmd = string(command)
	args = argsSplits
	return
}

func UnsealEnv(symetricKey []byte, sealRef string, sealEnv string, envIn []string, config map[string]string) (env []string, err error) {
	env = make([]string, 0)
	sd, err := Unseal(symetricKey, sealRef, sealEnv)
	if err != nil {
		err = fmt.Errorf("failed to decrypt args: %w", err)
		return
	}
	for k, v := range sd.UnsealedMap {
		if len(v) > 0 {
			env = append(env, fmt.Sprintf("%s=%s", k, string(v)))
			continue
		}
	}
	envExempt := config["EnvExempt"]
	exemptions := strings.Split(envExempt, ",")
	logger := log.Log
	logger.Infof("---UnsealEnv---")
	sdEnv := NewSealData()

	for _, element := range envIn {
		k, v, found := strings.Cut(element, "=")
		if !found || k == "" || v == "" {
			logger.Infof("Skip bad env '%s'", element)
			continue
		}
		// skip all SEAL env variables
		if strings.HasPrefix(k, "_SEAL_") {
			continue
		}
		if !isSealedString(v) {
			if slices.Contains(exemptions, k) {
				logger.Debugf("Exampt unsealed env '%s'", element)
				env = append(env, element)
			} else {
				logger.Infof("Skip unsealed env '%s'", element)
			}
			continue
		}

		// sealed env variables
		sealed, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			logger.Infof("Skip sealed env, base64: '%s'", element)
			continue
		}

		unsealed, err := sdEnv.DecryptItem(symetricKey, "", sealed)
		if err != nil {
			logger.Infof("Skip sealed env, decrypt: '%s'", element)
			continue
		}
		logger.Debugf("Add env: %s", k)
		env = append(env, fmt.Sprintf("%s=%s", k, string(unsealed)))
	}
	return env, nil
}

func UnsealMount(symetricKey []byte, sealRef string, sealMount string, config map[string]string) (mounts []string, err error) {
	sd, err := Unseal(symetricKey, sealRef, sealMount)
	if err != nil {
		return
	}
	mounts = make([]string, 0)
	for _, v := range sd.UnsealedMap {
		mounts = append(mounts, string(v))
	}
	return
}

func UnsealDir(srcname string, dstname string, symetricKey []byte, sealRef string, sealDir string, config map[string]string) error {
	sd, err := Unseal(symetricKey, sealRef, sealDir)
	if err != nil {
		return fmt.Errorf("failed to decrypt dirs: %w", err)
	}
	dirs := make([]string, 0)
	for _, v := range sd.UnsealedMap {
		dirs = append(dirs, string(v))
	}

	logger := log.Log
	logger.Infof("---UnsealDir--- %s => %s", srcname, dstname)
	err = filepath.WalkDir(srcname,
		func(cur_src string, d fs.DirEntry, err error) error {
			if d == nil {
				logger.Infof("UnsealDir found no directory to unseal: %v", err)
				return nil
			}
			cur_dest := filepath.Join(dstname, strings.TrimPrefix(cur_src, srcname))
			if d.IsDir() {
				if err != nil {
					logger.Infof("UnsealDir found a directory that cannot be traversed unseal: %v", err)
					return nil
				}
				if strings.HasPrefix(path.Base(cur_src), "..") {
					return filepath.SkipDir
				}
				if UnsealFiles(cur_src, cur_dest) {
					// skip directory - already processed!
					return filepath.SkipDir
				}
			} else {
				var ok bool
				for _, d := range dirs {
					if strings.HasPrefix(cur_dest, d) {
						ok = true
					}
				}
				if !ok {
					logger.Infof("Skip destination %s", cur_dest)
					return nil
				}
				if strings.HasPrefix(path.Base(cur_src), "..") {
					return nil
				}
				// found file in a non-skipped directory
				UnsealFile(cur_src, cur_dest, symetricKey, config)
			}
			return nil
		})
	if err != nil {
		logger.Infof("WalkDir error during UnsealDir: %v", err)
	}
	return err
}
func UnsealFile(src_path string, dest_path string, symetricKey []byte, options map[string]string) {
	logger := log.Log
	f, err := os.Open(src_path)
	if err != nil {
		logger.Infof("Failed to open file '%s': %v", src_path, err)
		return
	}
	defer f.Close()

	base64sealed := make([]byte, 1e+6)
	n, err := f.Read(base64sealed)
	if err != nil {
		logger.Infof("Failed to read file '%s': %v", src_path, err)
		return
	}
	base64sealed = base64sealed[:n]
	if !bytes.Equal(base64sealed[:8], []byte(sealedPrefixString)) {
		logger.Infof("Skip unsealed data at '%s'", src_path)
		return
	}

	// base64 decode of
	sealed := make([]byte, base64.StdEncoding.DecodedLen(n))
	n, err = base64.StdEncoding.Decode(sealed, base64sealed)
	if err != nil {
		logger.Infof("File '%s' has ilegal base64 : %v", src_path, err)
		return
	}
	sealed = sealed[:n]

	sd := NewSealData()
	unsealed, err := sd.DecryptItem(symetricKey, "", sealed)
	if err != nil {
		logger.Infof("Failed to Decrypt File '%s': - %v", src_path, err)
		return
	}
	AddFile(dest_path, unsealed, options)
}

func UnsealFiles(src_path string, dest_path string) bool {
	logger := log.Log
	err := os.MkdirAll(dest_path, 0777)
	if err != nil {
		logger.Infof("Failed to create directory %s: %v", dest_path, err)
		return true
	}
	return false
}

func AddFile(path string, data []byte, options map[string]string) {
	logger := log.Log

	nf, err := os.Create(path)
	if err != nil {
		logger.Infof("Failed to create new file %s: %v", path, err)
		return
	}
	defer nf.Close()

	_, err = nf.Write(data)
	if err != nil {
		logger.Infof("Failed to write new file %s: %v", path, err)
		return
	}
	logger.Debugf("Add file '%s'", path)
}
