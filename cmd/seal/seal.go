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
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/davidhadas/seal-control/pkg/log"
)

func main() {
	log.InitLog("Debug")
	var args []string

	if len(os.Args) < 2 {
		help()
		os.Exit(2)
	}
	args = os.Args[1:]

	switch args[0] {
	case "sys", "system":
		if !sys(args[1:]) {
			os.Exit(2)
		}
	case "wl", "workload":
		if !wl(args[1:]) {
			os.Exit(2)
		}
	case "-h":
		help()
	default:
		help()
		os.Exit(2)

	}
}

func help() {
	fmt.Printf("Seal controls resources to secure remote workloads\n\n")
	fmt.Printf("Commands:\n\n")
	fmt.Println("  Seal sys (system)  Control the Seal system")
	fmt.Println("  seal wl (workload) Control workloads")
	options()
	os.Exit(3)
}

func options() {
	fmt.Printf("\nOptions:\n\n")
	fmt.Println("  -help (-h)  Show this help")
	fmt.Println("  -f  		   Configuration file name")
}

func askForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n%s\n\tAre you sure [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return false
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}
