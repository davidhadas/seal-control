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
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/davidhadas/seal-control/pkg/certificates"
	"github.com/davidhadas/seal-control/pkg/log"
)

// WIP

func main() {
	var devEnvFlag bool // True if we are running in development environment

	log.InitLog("Debug")
	logger := log.Log

	logger.Infof("Seal wrap starting")

	var eegg []byte
	var err error
	eegg, err = os.ReadFile("/egg.txt")
	if err != nil {
		logger.Infof("Seal wrap: Failed to get egg: %s", err.Error())
		// no egg! lets check if we are in dev environment
		eegg, err = os.ReadFile("cmd/seal-wrap/kodata/egg.txt")
		if err != nil {
			logger.Infof("Seal wrap: Failed to get egg: %s", err.Error())
			eegg, err = os.ReadFile("./kodata/egg.txt")
		}
		if err != nil {
			logger.Infof("Seal wrap: Failed to get egg: %s", err.Error())
			cwd, _ := os.Getwd()
			logger.Infof("cwd: %s", cwd)
			os.Exit(1)
		}
		devEnvFlag = true
	}

	hostnames := os.Getenv("HOSTNAMES")
	hsplits := strings.Split(hostnames, ",")
	for _, h := range hsplits {
		if err := certificates.ValidateHostname(h); err != nil {
			logger.Infof("Seal wrap: Ilegal hostname in env HOSTNAMES '%s': %v", h, err)
			os.Exit(1)
		}
		logger.Infof("Seal wrap: Adding hostname '%s'", h)
	}

	podData, err := certificates.Rot_client(string(eegg), hsplits)
	if err != nil {
		logger.Infof("Seal wrap: Failed to get podMassage:", err)
		os.Exit(1)
	}

	wks, current, err := podData.GetWKeysFromPodData()
	if err != nil {
		logger.Infof("Seal wrap: Failed to get workload keys:", err)
		os.Exit(1)
	}
	wKey := wks[current]

	sealRef := os.Getenv("_SEAL_REF")
	sealConfig := os.Getenv("_SEAL_CONFIG")
	sealEnv := os.Getenv("_SEAL_ENV")

	if err != nil {
		logger.Infof("Seal wrap: cannot find _SEAL_REF")
		os.Exit(1)
	}

	options, err := get_config(wKey, sealRef, sealConfig)
	if err != nil {
		logger.Infof("Seal wrap: cannot find confiuration: %v", err)
		os.Exit(1)
	}

	logger.Infof("Seal wrap cofig: %v", options)

	if err := check_mounts(devEnvFlag, options); err != nil {
		logger.Infof("Seal wrap: Ilegal mounts: %v", err)
		os.Exit(1)
	}

	err = certificates.UnsealDir("/run/seal/", "/", wKey, options)
	if err != nil {
		logger.Infof("failed to UnsealDir: %v", err)
		return
	}

	env, err := certificates.UnsealEnv(wKey, sealEnv, options)
	if err != nil {
		logger.Infof("failed to UnsealEnv: %v", err)
		return
	}

	cmd, args, err := certificates.UnsealArgs(wKey, options, sealRef)
	if err != nil {
		logger.Infof("failed to UnsealArgs: %v", err)
		return
	}
	if cmd == "" {
		logger.Infoln("UnsealArgs  - no CMD or ARGS found")
	} else {
		logger.Infof("Starting process '%s %s'", cmd, strings.Join(args, " "))
		for _, str := range env {
			logger.Debugf("\t%s", str)
		}
		go startProcess(cmd, args, env)
	}
	for {
		fmt.Println("Tick")
		time.Sleep(10 * time.Second)
	}
}

func get_config(wKey []byte, sealRef string, sealConfigStr string) (map[string]string, error) {
	sealed, err := base64.StdEncoding.DecodeString(sealConfigStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode - should be Base64 '%s' - err %v", os.Args[0], err)
	}
	sdAnnotation := certificates.NewSealData()
	err = sdAnnotation.Decrypt(wKey, sealRef, sealed)
	if err != nil {
		return nil, fmt.Errorf("failed to Decrypt Seal Config: %w", err)
	}
	options := make(map[string]string)
	for k, v := range sdAnnotation.UnsealedMap {
		options[k] = string(v)
	}

	return options, nil
}

func startProcess(cmd string, args []string, env []string) {
	command := exec.Command(cmd, args...)
	command.Env = env
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		fmt.Printf("Failed to Run: %v", err)
		os.Exit(-1)
	}
	os.Exit(0)
}
