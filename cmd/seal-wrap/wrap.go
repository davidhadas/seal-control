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
	log.InitLog("Debug")
	logger := log.Log

	logger.Infof("Seal wrap starting")
	logger.Sync()

	var eegg []byte
	var err error
	var devEnvFlag bool // True if we are running in development environment

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
			exit()
		}
		devEnvFlag = true
	}

	hostnames := os.Getenv("HOSTNAMES")
	hsplits := strings.Split(hostnames, ",")
	for _, h := range hsplits {
		if err := certificates.ValidateHostname(h); err != nil {
			logger.Infof("Seal wrap: Ilegal hostname in env HOSTNAMES '%s': %v", h, err)
			exit()
		}
		logger.Infof("Seal wrap: Adding hostname '%s'", h)
	}

	podData, err := certificates.Rot_client(string(eegg), hsplits)
	if err != nil {
		logger.Infof("Seal wrap: Failed to get podMassage:", err)
		exit()
	}

	wks, current, err := podData.GetWKeysFromPodData()
	if err != nil {
		logger.Infof("Seal wrap: Failed to get workload keys:", err)
		exit()
	}
	wKey := wks[current]

	sealConfig := os.Getenv(certificates.SEAL_CONFIG)
	sealEnv := os.Getenv(certificates.SEAL_ENV)
	sealDir := os.Getenv(certificates.SEAL_DIR)
	sealMount := os.Getenv(certificates.SEAL_MOUNT)
	sealRef := os.Getenv(certificates.SEAL_REF)
	if sealRef == "" {
		logger.Infof("Seal wrap: cannot find SEAL_REF")
		exit()
	}

	config, err := certificates.UnsealConfig(wKey, "config"+sealRef, sealConfig)
	if err != nil {
		logger.Infof("Seal wrap: cannot obtain configuration: %v", err)
		exit()
	}
	logger.Infof("Seal wrap cofig: %v", config)

	mounts, err := certificates.UnsealMount(wKey, "mount"+sealRef, sealMount, config)
	if err != nil {
		logger.Infof("failed to UnsealMount: %v", err)
		exit()
	}
	if err := check_mounts(devEnvFlag, mounts, config); err != nil {
		logger.Infof("Seal wrap: Ilegal mounts: %v", err)
		exit()
	}

	// Check if /etc/hosts, /etc/hostname, /etc/resolv.conf are legit
	err = testHostname(devEnvFlag)
	if err != nil {
		logger.Infof("/etc/hostname: %v\n", err)
		exit()
	}
	err = testHosts(devEnvFlag)
	if err != nil {
		logger.Infof("/etc/hosts: %v\n", err)
		exit()
	}
	err = testResolv(devEnvFlag)
	if err != nil {
		logger.Infof("/etc/resolv.conf: %v\n ", err)
		exit()
	}

	err = certificates.UnsealDir(certificates.SEAL_MOUNTPOINT, "/", wKey, "dir"+sealRef, sealDir, config)
	if err != nil {
		logger.Infof("failed to UnsealDir: %v", err)
		exit()
	}

	env, err := certificates.UnsealEnv(wKey, "env"+sealRef, sealEnv, os.Environ(), config)
	if err != nil {
		logger.Infof("failed to UnsealEnv: %v", err)
		exit()
	}

	cmd, args, err := certificates.UnsealArgs(wKey, "args"+sealRef, os.Args, config)
	if err != nil {
		logger.Infof("failed to UnsealArgs: %v", err)
		exit()
	}
	if cmd == "" {
		logger.Infoln("UnsealArgs  - no CMD or ARGS found")
	} else {
		logger.Infof("Starting process '%s %s'", cmd, strings.Join(args, " "))
		logger.Infof("  Env of process:")
		for _, str := range env {
			logger.Debugf("\t%s", str)
		}
		go startProcess(cmd, args, env)
	}

	for {
		fmt.Println("Background Monitor Tick")
		time.Sleep(60 * time.Second)
	}
}

func exit() {
	fmt.Println("Exiting...")
	time.Sleep(60 * time.Second)
	fmt.Println("Done...")
	os.Exit(0)
}

func startProcess(cmd string, args []string, env []string) {
	command := exec.Command(cmd, args...)
	command.Env = env
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Error while Running: %s - error %v", cmd, exitError)
			exit()
		}
		fmt.Printf("Failed to Run: %v", err)
	}
	exit()
}
