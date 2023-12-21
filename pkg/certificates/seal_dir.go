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

func UnsealArgs(symetricKey []byte, options map[string]string) (cmd string, args []string, err error) {
	if len(os.Args) != 2 {
		err = fmt.Errorf("Wrong number of arguments - should be '<Cyphertext>'")
		return
	}
	if !isSealedString(os.Args[1]) {
		err = fmt.Errorf("Argument should be sealed")
		return
	}
	sealed, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil {
		err = fmt.Errorf("Failed to decode - should be Base64 '%s' - err %v", os.Args[0], err)
		return
	}

	sd := NewSealData()
	err = sd.Decrypt(symetricKey, "args", sealed)
	if err != nil {
		err = fmt.Errorf("Failed to Decrypt Args: %w", err)
		return
	}

	numArgs := len(sd.UnsealedMap)
	if numArgs < 1 {
		err = fmt.Errorf("Failed to find EntryPoint in sealed Args")
		return
	}
	command, ok := sd.UnsealedMap["0"]
	if !ok {
		err = fmt.Errorf("Failed to find EntryPoint in location 0 of sealed args")
		return
	}
	argsSplits := make([]string, numArgs-1)
	for i := 1; i < numArgs; i++ {
		val, ok := sd.UnsealedMap[strconv.Itoa(i)]
		if !ok {
			err = fmt.Errorf("Wrong args structure")
			return
		}
		argsSplits[i-1] = string(val)
	}
	cmd = string(command)
	args = argsSplits
	return
}

func UnsealEnv(symetricKey []byte, options map[string]string) ([]string, error) {
	logger := log.Log
	logger.Infof("----------------UnsealEnv------------")
	envExempt := options["EnvExempt"]
	exemptions := strings.Split(envExempt, ",")

	sd := NewSealData()
	env := []string{}
	for _, element := range os.Environ() {
		k, v, found := strings.Cut(element, "=")
		if !found || k == "" || v == "" {
			logger.Infof("Skip bad envrioment variable '%s'", element)
			continue
		}
		if slices.Contains(exemptions, k) {
			env = append(env, element)
			continue
		}

		if !isSealedString(v) {
			continue
		}
		sealed, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			continue
		}
		unsealed, err := sd.DecryptItem(symetricKey, "", sealed)
		if err != nil {
			continue
		}
		logger.Debugf("UnsealEnv added: key %s", k)
		env = append(env, fmt.Sprintf("%s=%s", k, string(unsealed)))
	}
	return env, nil
}

func UnsealDir(srcname string, dstname string, symetricKey []byte, options map[string]string) error {
	logger := log.Log
	err := filepath.WalkDir(srcname,
		func(cur_path string, d fs.DirEntry, err error) error {
			if d == nil {
				logger.Infof("UnsealDir found no directory to unseal: %v", err)
				return nil
			}

			if d.IsDir() {
				if err != nil {
					logger.Infof("UnsealDir found a directoרy that cannot be traversed unseal: %v", err)
					return nil
				}
				if strings.HasPrefix(path.Base(cur_path), "..") {
					//logger.Infof("UnsealDir skipping DIR %s (%s)", cur_path, path.Base(cur_path))
					return filepath.SkipDir
				}
				if UnsealFiles(srcname, cur_path, dstname, symetricKey, options) {
					// skip directory - already processed!
					return filepath.SkipDir
				}
			} else {
				if strings.HasPrefix(path.Base(cur_path), "..") {
					//logger.Infof("UnsealDir skipping File %s (%s)", cur_path, path.Base(cur_path))
					return nil
				}
				// found file in a non-skipped directory
				UnsealFile(srcname, cur_path, dstname, symetricKey, options)
			}
			return nil
		})
	if err != nil {
		logger.Infof("WalkDir error during UnsealDir: %v", err)
	}
	return err
}
func UnsealFile(srcname string, fpath string, dstname string, symetricKey []byte, options map[string]string) {
	logger := log.Log
	logger.Debugf("UnsealFile %s", fpath)

	f, err := os.Open(fpath)
	if err != nil {
		logger.Infof("Failed to read file %s: %v", fpath, err)
		return
	}
	defer f.Close()

	base64sealed := make([]byte, 1e+6)
	n, err := f.Read(base64sealed)
	if err != nil {
		logger.Infof("Failed to read file %s: %v", fpath, err)
		return
	}
	base64sealed = base64sealed[:n]

	// base64 decode of
	sealed := make([]byte, base64.StdEncoding.DecodedLen(n))
	n, err = base64.StdEncoding.Decode(sealed, base64sealed)
	if err != nil {
		logger.Infof("File %s has ilegal base64 : %v", fpath, err)
		return
	}
	sealed = sealed[:n]

	sd := NewSealData()
	unsealed, err := sd.DecryptItem(symetricKey, "", sealed)
	if err != nil {
		logger.Infof("Failed to Decrypt File %s: %v - %v", fpath, sealed, err)
		return
	}
	newpath := filepath.Join(dstname, strings.TrimPrefix(fpath, srcname))
	AddFile(newpath, unsealed, options)
}

func UnsealFiles(srcname string, dirname string, dstname string, symetricKey []byte, options map[string]string) bool {
	logger := log.Log
	dstname = filepath.Join(dstname, strings.TrimPrefix(dirname, srcname))
	err := os.MkdirAll(dstname, 0777)
	if err != nil {
		logger.Infof("Failed to create directory %s: %v", dstname, err)
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
}
