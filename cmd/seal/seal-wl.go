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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/davidhadas/seal-control/pkg/certificates"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func wl(args []string) bool {
	err := certificates.InitRotKubeMgr()
	if err != nil {
		fmt.Printf("Failed to access local kubernetes cluster: %v\n", err)
		return false
	}
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
	if len(args) == 0 {
		fmt.Printf("List of worklodas:\n")
		cas, err := certificates.KubeMgr.ListCas()
		if err != nil {
			fmt.Printf("Failed to list workload secrets: %v\n", err)
			return false
		}
		if len(cas) == 0 {
			fmt.Printf("  (Empty)\n")
		}
		for _, ca := range cas {
			fmt.Printf("  %s\n", ca)
		}
		return true
	}
	workload := os.Args[2]
	err = certificates.ValidateWorkloadName(workload)
	if err != nil {
		if workload == "-h" {
			wl_help()
			return true
		} else {
			fmt.Printf("Ilegal workload name: %v\n", err)
		}
		return false
	}
	args = args[1:]
	if len(args) == 0 {
		workloadCaKeyRing, err := certificates.GetCA(workload)
		if err != nil {
			if apierrors.IsNotFound(err) {
				fmt.Printf("Failed to load workload CA: %v\n", err)
				fmt.Printf("Initialize workload CA using\n\t`wl %s init`\n", workload)
				return false
			}
			fmt.Printf("Cant access workload CA: %v\n", err)
			return false
		}
		fmt.Printf("Seal workload %s:\n", workload)
		fmt.Printf("  ROT URL:      %s\n", workloadCaKeyRing.RotUrl())
		fmt.Printf("  Certs:        %d\n", workloadCaKeyRing.NumCerts())
		fmt.Printf("  PrivateKeys:  %d\n", workloadCaKeyRing.NumPrivateKeys())
		fmt.Printf("  SymetricKeys: %d\n", workloadCaKeyRing.NumSymetricKeys())
		fmt.Printf("  Peers:\n")
		peers := workloadCaKeyRing.Peers()
		if len(peers) == 0 {
			fmt.Printf("    (Empty)\n")
		}
		for client, servers := range peers {
			fmt.Printf("    %s => %s\n", client, servers)
		}
		return true
	}

	switch args[0] {
	case "apply":
		workloadCaKeyRing, err := certificates.GetCA(workload)
		if err != nil {
			if apierrors.IsNotFound(err) {
				fmt.Printf("Failed to load workload CA: %v\n", err)
				fmt.Printf("Initialize workload CA using\n\t`wl %s init`\n", workload)
				return false
			}
			fmt.Printf("Cant access workload CA: %v\n", err)
			return false
		}
		return apply(workloadCaKeyRing, args[1:])
	case "init":
		if len(args) > 1 {
			wl_help()
			return false
		} else {
			rotUrl := certificates.KubeMgr.RotCaKeyRing.RotUrl()
			return wl_init(workload, rotUrl)
		}
	case "del", "delete":
		if len(args) > 1 {
			wl_help()
			return false
		} else {
			return wl_del(workload)
		}
	case "egg":
		return wl_egg(workload, args[1:])
	case "cert":
		return wl_cert(workload, args[1:])
	case "client":
		workloadCaKeyRing, err := certificates.GetCA(workload)
		if err != nil {
			if apierrors.IsNotFound(err) {
				fmt.Printf("Failed to load workload CA: %v\n", err)
				fmt.Printf("Initialize workload CA using\n\t`wl %s init`\n", workload)
				return false
			}
			fmt.Printf("Cant access workload CA: %v\n", err)
			return false
		}
		return wl_connect(workloadCaKeyRing, workload, args[1:])
	case "-h":
		wl_help()
		return true
	default:
		wl_help()
		return false
	}
}

func wl_help() {
	fmt.Printf("Control a Seal workload\n\n")
	fmt.Printf("Subcommands:\n\n")
	fmt.Printf("  seal wl\n")
	fmt.Printf("  seal wl <Workload-Name>\n")
	fmt.Printf("  seal wl <Workload-Name> apply -f -\n")
	fmt.Printf("  seal wl <Workload-Name> apply -f [<Filename>]+\n")
	fmt.Printf("  seal wl <Workload-Name> del\n")
	fmt.Printf("  seal wl <Workload-Name> init\n")
	fmt.Printf("  seal wl <Workload-Name> egg\n")
	fmt.Printf("  seal wl <Workload-Name> cert\n")
	fmt.Printf("  seal wl <Workload-Name> egg <Name>\n")
	fmt.Printf("  seal wl <Workload-Name> cert <Name>\n")
	fmt.Printf("  seal wl <Workload-Name> client <Name>\n")
	fmt.Printf("  seal wl <Workload-Name> client <Name> servers [ <Name>]*\n")
}

func wl_connect(workloadCaKeyRing *certificates.KeyRing, workload string, args []string) bool {
	var client string
	var servers []string
	if len(args) == 0 {
		wl_help()
		return false
	}
	// one or more args
	client = args[0]
	err := certificates.ValidateSevriceName(client)
	if err != nil {
		fmt.Printf("Ilegal client service name: %v\n", err)
		return false
	}

	args = args[1:]
	if len(args) == 0 {
		servers = []string{"any"}
	} else {
		// more than one args
		if args[0] != "servers" {
			wl_help()
			return false
		}
		args = args[1:]

		servers = []string(make([]string, 0))
		for _, server := range args {
			err = certificates.ValidateSevriceName(server)
			if err != nil {
				fmt.Printf("Ilegal server service name: %v\n", err)
				return false
			}
			servers = append(servers, server)
		}
	}
	workloadCaKeyRing.AddPeer(client, strings.Join(servers, ","))

	err = certificates.UpdateCA(workload, workloadCaKeyRing)
	if err != nil {
		fmt.Printf("Failed to update secret: %v\n", err)
		return false
	}
	return true
}

func wl_init(workload string, rotUrl string) bool {
	if !certificates.CANotFound(workload) {
		fmt.Printf("Delete ROT CA first\n\t`wl %s del`\n", workload)
		return false
	}
	fmt.Printf("Initializing workload `%s` CA Secret\n", workload)

	keyRing, err := certificates.CreateNewCA(workload, rotUrl)
	if err != nil {
		fmt.Printf("Failed to create a new workload CA: %v\n", err)
		return false
	}

	fmt.Printf("Seal workload `%s`:\n", workload)
	fmt.Printf("  RotUrl:       %s\n", keyRing.RotUrl())
	fmt.Printf("  Certs:        %d\n", keyRing.NumCerts())
	fmt.Printf("  PrivateKeys:  %d\n", keyRing.NumPrivateKeys())
	fmt.Printf("  SymetricKeys: %d\n", keyRing.NumSymetricKeys())
	return true
}

func wl_del(workload string) bool {
	if certificates.CANotFound(workload) {
		fmt.Printf("Workload `%s` CA does not exist\n", workload)
		return false
	}
	fmt.Printf("\t******************\n")
	fmt.Printf("\t*** WARNING!!! ***\n")
	fmt.Printf("\t******************\n")
	fmt.Printf("\n")
	fmt.Printf("This is a destructive action that deletes workload `%s` CA\n", workload)
	fmt.Printf("Once a new workload CA is created, all workload images will need to be restarted\n")

	if askForConfirmation("") {
		certificates.KubeMgr.DeleteCa(workload)
	}
	return true
}

func wl_cert(workload string, args []string) bool {
	var servicename string
	switch len(args) {
	case 0:
		servicename = "any"
	case 1:
		servicename = args[0]
	default:
		wl_help()
		return false
	}

	err := certificates.ValidateSevriceName(servicename)
	if err != nil {
		fmt.Printf("Ilegal service name: %v\n", err)
		return false
	}

	var certificate *x509.Certificate
	var cacertificates []*x509.Certificate

	pmr, err := certificates.NewPodMessageReq(workload, servicename)
	if err != nil {
		fmt.Printf("Failed to create PodMessageReq: %v\n", err)
		return false
	}
	podMessage, err := certificates.CreatePodMessage(pmr)
	if err != nil {
		fmt.Printf("Failed to CreatePodMessage: %v\n", err)
		return false
	}
	podData := certificates.NewPodData(pmr, podMessage)

	cas, err := podData.GetCaPem()
	if err != nil {
		fmt.Printf("Failed to get CA Pem: %v\n", err)
		return false
	}

	cert, err := podData.GetCert()
	if err != nil {
		fmt.Printf("Failed to get Cert Pem: %v\n", err)
		return false
	}
	pkeyPem := podData.GetPrivateKeyPem()

	err = toFile("ca.pem", cas)
	if err != nil {
		fmt.Printf("Failed creating CA PEM: %v\n", err)
		return false
	}
	block, _ := pem.Decode(cert)
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("tls.ParseCertificate cert failed: %v\n", err)
		return false
	}
	block, _ = pem.Decode(cas)
	certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("tls.ParseCertificate ca failed: %v\n", err)
		return false
	}
	encoder := pkcs12.Encoder{}
	pfx, err := encoder.Encode(pkeyPem, certificate, cacertificates, "")
	if err != nil {
		fmt.Printf("encoder.Encode pkcs12 certificate failed: %v\n", err)
		return false
	}
	err = toFile("certificate.pfx", pfx)
	if err != nil {
		fmt.Printf("Failed creating PRK PEM: %v\n", err)
		return false
	}

	err = toFile("cert.pem", cert)
	if err != nil {
		fmt.Printf("Failed creating CERT PEM: %v\n", err)
		return false
	}
	err = toFile("prk.pem", []byte(pkeyPem))
	if err != nil {
		fmt.Printf("Failed creating PRK PEM: %v\n", err)
		return false
	}
	fmt.Printf("ca.pem, cert.pem, prk.pem, certificate.pfx files created\n")
	return true
}

func toFile(filename string, data []byte) error {
	f, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer f.Close()

	_, err = f.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("failed to write to file %s: %v", filename, err)
	}
	return nil
}

func wl_egg(workload string, args []string) bool {
	var servicename string
	switch len(args) {
	case 0:
		servicename = "any"
	case 1:
		servicename = args[0]
	default:
		wl_help()
		return false
	}

	err := certificates.ValidateSevriceName(servicename)
	if err != nil {
		fmt.Printf("Ilegal service name: %v\n", err)
		return false
	}

	egg, err := certificates.CreateInit(workload, servicename)
	if err != nil {
		fmt.Printf("Failed to create egg: %v\n", err)
		return false
	}
	eegg, err := egg.Encode()
	if err != nil {
		fmt.Printf("Failed to encode egg: %v\n", err)
		return false
	}
	fmt.Println(eegg)
	return true
}
