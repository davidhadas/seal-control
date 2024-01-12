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
	"fmt"

	"github.com/davidhadas/seal-control/pkg/certificates"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func sys(args []string) bool {
	err := certificates.InitRotKubeMgr()
	if err != nil {
		fmt.Printf("Failed to access local kubernetes cluster: %v\n", err)
		return false
	}

	if len(args) == 0 {
		err = certificates.LoadRotCa()
		if err != nil {
			if apierrors.IsNotFound(err) {
				fmt.Printf("Failed to load ROT CA: %v\n", err)
				fmt.Printf("** Verify that kubectl points to the ROT cluster ** \n")
				fmt.Printf("   Initialize ROT CA using\n\t`sys init <ROT-URL>`\n")
				return false
			}
			fmt.Printf("Cant access ROT CA: %v\n", err)
			return false
		}
		fmt.Println("Seal system:")
		fmt.Printf("  RotUrl:       %s\n", certificates.KubeMgr.RotCaKeyRing.RotUrl())
		fmt.Printf("  Certs:        %d\n", certificates.KubeMgr.RotCaKeyRing.NumCerts())
		fmt.Printf("  PrivateKeys:  %d\n", certificates.KubeMgr.RotCaKeyRing.NumPrivateKeys())
		fmt.Printf("  SymetricKeys: %d\n", certificates.KubeMgr.RotCaKeyRing.NumSymetricKeys())
		return false
	}
	switch args[0] {
	case "del", "delete":
		return sys_del(args[1:])
	case "init":
		return sys_init(args[1:])
	case "url":
		return sys_url(args[1:])
	default:
		sys_help()
		return false
	}
}

func sys_init(args []string) bool {
	if len(args) != 1 {
		sys_help()
		return false
	}
	if args[0] == "-h" {
		sys_help()
		return true
	}
	rotUrl := args[0]

	if !certificates.CANotFound("") {
		fmt.Printf("Delete ROT CA first\n\t`sys del`\n")
		return false
	}
	fmt.Printf("Initializing ROT CA Secret with URL %s\n", rotUrl)

	keyRing, err := certificates.CreateNewCA("", rotUrl)
	if err != nil {
		fmt.Printf("Failed to create a new ROT CA: %v\n", err)
		return false
	}
	certificates.KubeMgr.RotCaKeyRing = keyRing
	fmt.Println("Seal system:")
	fmt.Printf("  RotUrl:       %s\n", certificates.KubeMgr.RotCaKeyRing.RotUrl())
	fmt.Printf("  Certs:        %d\n", certificates.KubeMgr.RotCaKeyRing.NumCerts())
	fmt.Printf("  PrivateKeys:  %d\n", certificates.KubeMgr.RotCaKeyRing.NumPrivateKeys())
	fmt.Printf("  SymetricKeys: %d\n", certificates.KubeMgr.RotCaKeyRing.NumSymetricKeys())
	return true
}

func sys_url(args []string) bool {
	if len(args) != 1 {
		sys_help()
		return false
	}
	if args[0] == "-h" {
		sys_help()
		return true
	}
	rotUrl := args[0]

	err := certificates.LoadRotCa()
	if err != nil {
		if apierrors.IsNotFound(err) {
			fmt.Printf("Failed to load ROT CA: %v\n", err)
			fmt.Printf("** Verify that kubectl points to the ROT cluster ** \n")
			fmt.Printf("   Initialize ROT CA using\n\t`sys init <ROT-URL>`\n")
			return false
		}
		fmt.Printf("Cant access ROT CA: %v\n", err)
		return false
	}

	err = certificates.KubeMgr.RotCaKeyRing.SetRotUrl(rotUrl)
	if err != nil {
		fmt.Printf("%v", err)
		return false
	}
	err = certificates.UpdateCA("", certificates.KubeMgr.RotCaKeyRing)
	if err != nil {
		fmt.Printf("Failed to update ROT CA: %v\n", err)
		return false
	}
	return true
}

func sys_del(args []string) bool {
	if len(args) != 0 {
		sys_help()
		return false
	}

	if certificates.CANotFound("") {
		fmt.Printf("ROT CA does not exist\n")
		return false
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
		return false
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
	return true
}

// https://192.168.68.102:8443/rot
// https://127.0.0.1:8443/

func sys_help() {
	fmt.Printf("Control the Seal system\n\n")
	fmt.Printf("Subcommands:\n\n")
	fmt.Printf("  seal sys\n")
	fmt.Printf("  seal sys del\n")
	fmt.Printf("  seal sys init <ROT-URL>\n")
	fmt.Printf("  seal sys url <ROT-URL>\n")
}
