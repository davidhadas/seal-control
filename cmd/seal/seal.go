/*
Copyright 2022 The Knative Authors

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
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/davidhadas/seal-control/pkg/log"
)

var hFlag *bool
var helpFlag *bool

func main() {
	log.InitLog()
	flag.Usage = help
	hFlag = flag.Bool("h", false, "h")
	helpFlag = flag.Bool("help", false, "help")

	flag.Parse()

	if len(os.Args) < 2 {
		help()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "sys", "system":
		sys()
	case "wl", "workload":
		wl()
	}
	return
}

func help() {
	fmt.Printf("Seal controls resources to secure remote workloads\n\n")
	fmt.Printf("Commands:\n\n")
	fmt.Println("  system (sys)  Control the Seal system")
	fmt.Println("  workload (wl) Control workloads")
	options()
}

func options() {
	fmt.Printf("\nOptions:\n\n")
	fmt.Println("  -help (-h)  Show this help")
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
