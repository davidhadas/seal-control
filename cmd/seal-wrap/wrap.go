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
	eggpath := "/egg.txt"

	eegg, err := os.ReadFile(eggpath)
	if err != nil {
		logger.Infof("Seal wrap: Failed to get egg:", err)
		os.Exit(1)
	}

	hostnames := os.Getenv("HOSTNAMES")
	hsplits := strings.Split(hostnames, ",")
	for _, h := range hsplits {
		if err := certificates.ValidateHostname(h); err != nil {
			logger.Infof("Seal wrap: Ilegal hostname '%s': %v", h, err)
			os.Exit(1)
		}
		logger.Infof("Seal wrap: Adding hostname '%s'", h)
	}

	podMessage, options, err := certificates.Rot_client(string(eegg), hsplits)
	if err != nil {
		logger.Infof("Seal wrap: Failed to get podMassage:", err)
		os.Exit(1)
	}

	wks, current, err := certificates.GetWKeysFromPodMessage(podMessage)
	if err != nil {
		logger.Infof("Seal wrap: Failed to get workload keys:", err)
		os.Exit(1)
	}
	wKey := wks[current]

	err = certificates.UnsealDir("/sealed", "/unsealed", wKey, options)
	if err != nil {
		logger.Infof("failed to UnsealDir: %v", err)
		return
	}

	env, err := certificates.UnsealEnv(wKey, options)
	if err != nil {
		logger.Infof("failed to UnsealEnv: %v", err)
		return
	}

	cmd, args, err := certificates.UnsealArgs(wKey, options)
	if err != nil {
		logger.Infof("failed to UnsealArgs: %v", err)
		return
	}
	logger.Infof("Starting process %s %s", cmd, strings.Join(args, " "))
	for _, str := range env {
		logger.Debugf("\t%s", str)
	}
	go startProcess(cmd, args, env)
	for {
		time.Sleep(10 * time.Second)
		fmt.Println("Tick")
	}
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
