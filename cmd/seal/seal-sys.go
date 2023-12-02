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
	"fmt"
	"os"

	"github.com/davidhadas/seal-control/pkg/certificates"
)

func sys() {
	if *helpFlag || *hFlag {
		fmt.Println("-H")
		sys_help()
		os.Exit(1)
	}
	err := certificates.InitKubeMgr()
	if err != nil {
		fmt.Printf("Failed to access local kubernetes cluster: %v\n", err)
		return
	}

	switch len(os.Args) {
	case 2:
		err = certificates.LoadRotCa()
		if err != nil {
			fmt.Printf("Failed to load ROT CA: %v\n", err)
			fmt.Printf("Initialize ROT CA using\n\t`sys init <ROT-URL>`\n")
			return
		}
		fmt.Println("Seal system:")
		fmt.Printf("  RotUrl:       %s\n", certificates.KubeMgr.RotCaKeyRing.RotUrl())
		fmt.Printf("  Certs:        %d\n", certificates.KubeMgr.RotCaKeyRing.NumCerts())
		fmt.Printf("  PrivateKeys:  %d\n", certificates.KubeMgr.RotCaKeyRing.NumPrivateKeys())
		fmt.Printf("  SymetricKeys: %d\n", certificates.KubeMgr.RotCaKeyRing.NumSymetricKeys())
		return
	case 3:
		switch os.Args[2] {
		case "del", "delete":
			sys_del()
			return
		}
	case 4:
		switch os.Args[2] {
		case "init":
			sys_init(os.Args[3])
			return
		}
	}
	sys_help()
}

func sys_init(rotUrl string) {
	if !certificates.CANotFound("") {
		fmt.Printf("Delete ROT CA first\n\t`sys del`\n")
		return
	}
	fmt.Printf("Initializing ROT CA Secret with URL %s\n", rotUrl)

	keyRing, err := certificates.CreateNewCA("", rotUrl)
	if err != nil {
		fmt.Printf("Failed to create a new ROT CA: %v\n", err)
		return
	}
	certificates.KubeMgr.RotCaKeyRing = keyRing
	fmt.Println("Seal system:")
	fmt.Printf("  RotUrl:       %s\n", certificates.KubeMgr.RotCaKeyRing.RotUrl())
	fmt.Printf("  Certs:        %d\n", certificates.KubeMgr.RotCaKeyRing.NumCerts())
	fmt.Printf("  PrivateKeys:  %d\n", certificates.KubeMgr.RotCaKeyRing.NumPrivateKeys())
	fmt.Printf("  SymetricKeys: %d\n", certificates.KubeMgr.RotCaKeyRing.NumSymetricKeys())
}

func sys_del() {
	if certificates.CANotFound("") {
		fmt.Printf("ROT CA does not exist\n")
		return
	}
	fmt.Printf("\t******************\n")
	fmt.Printf("\t*** WARNING!!! ***\n")
	fmt.Printf("\t******************\n")
	fmt.Printf("\n")
	fmt.Printf("This is a destructive action that inlcudes:\n")
	fmt.Printf("\tDeleting ROT\n")
	cas, err := certificates.KubeMgr.ListCas()
	if err != nil {
		fmt.Printf("Failed to list workload secrets: %v\n", err)
		return
	}
	for _, ca := range cas {
		fmt.Printf("\tDeleting workload  `%s`\n", ca)
	}
	fmt.Printf("This action will delete ROT CA and all workload CAs\n")
	fmt.Printf("Once a new ROT CA is created, all workload images will need to be recreated\n")

	if askForConfirmation("") {
		for _, ca := range cas {
			certificates.KubeMgr.DeleteCa(ca)
		}
		certificates.KubeMgr.DeleteCa("")
	}
}

// https://192.168.68.102:8443/rot
// https://127.0.0.1:8443/

func sys_help() {
	fmt.Printf("Control the Seal system\n\n")
	fmt.Printf("Subcommands:\n\n")
	fmt.Printf("  seal sys\n")
	fmt.Printf("  seal sys del\n")
	fmt.Printf("  seal sys init <ROT-URL>\n")

}
