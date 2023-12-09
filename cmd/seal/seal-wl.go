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
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/davidhadas/seal-control/pkg/certificates"
)

func wl() {
	if *helpFlag || *hFlag {
		fmt.Println("-H")
		wl_help()
		os.Exit(1)
	}
	err := certificates.InitKubeMgr()
	if err != nil {
		fmt.Printf("Failed to access local kubernetes cluster: %v\n", err)
		return
	}
	err = certificates.LoadRotCa()
	if err != nil {
		fmt.Printf("Failed to load ROT CA: %v\n", err)
		fmt.Printf("Initialize ROT CA using\n\t`sys init <ROT-URL>`\n")
		return
	}
	numArgs := len(os.Args)
	switch {
	case numArgs == 2:
		fmt.Printf("List of worklodas:\n")
		cas, err := certificates.KubeMgr.ListCas()
		if err != nil {
			fmt.Printf("Failed to list workload secrets: %v\n", err)
			return
		}
		if len(cas) == 0 {
			fmt.Printf("  (Empty)\n")
		}
		for _, ca := range cas {
			fmt.Printf("  %s\n", ca)
		}
		return
	case numArgs == 3:
		workload := os.Args[2]
		err = certificates.ValidateWorkloadName(workload)
		if err != nil {
			fmt.Printf("Ilegal workload name: %v\n", err)
			return
		}
		caKeyRing, err := certificates.GetCA(workload)
		if err != nil {
			fmt.Printf("Failed to load workload CA: %v\n", err)
			fmt.Printf("Initialize workload CA using\n\t`wl %s init`\n", workload)
			return
		}
		fmt.Printf("Seal workload %s:\n", workload)
		fmt.Printf("  ROT URL:      %s\n", caKeyRing.RotUrl())
		fmt.Printf("  Certs:        %d\n", caKeyRing.NumCerts())
		fmt.Printf("  PrivateKeys:  %d\n", caKeyRing.NumPrivateKeys())
		fmt.Printf("  SymetricKeys: %d\n", caKeyRing.NumSymetricKeys())
		fmt.Printf("  Peers:\n")
		peers := caKeyRing.Peers()
		if len(peers) == 0 {
			fmt.Printf("    (Empty)\n")
		}
		for client, servers := range peers {
			fmt.Printf("    %s => %s\n", client, servers)
		}
		return
	case numArgs == 4:
		workload := os.Args[2]
		cmd := os.Args[3]
		err = certificates.ValidateWorkloadName(workload)
		if err != nil {
			fmt.Printf("Ilegal workload name: %v\n", err)
			return
		}
		if cmd == "init" {
			rotUrl := certificates.KubeMgr.RotCaKeyRing.RotUrl()
			wl_init(workload, rotUrl)
			return
		}
		if cmd == "del" || cmd == "delete" {
			wl_del(workload)
			return
		}

		switch cmd {
		case "egg":
			wl_egg(workload, "any")
			return
		case "cert":
			wl_cert(workload, "any")
			return
		}
	case numArgs == 5:
		workload := os.Args[2]
		err = certificates.ValidateWorkloadName(workload)
		if err != nil {
			fmt.Printf("Ilegal workload name: %v\n", err)
			return
		}
		_, err := certificates.GetCA(workload)
		if err != nil {
			fmt.Printf("Failed to load workload CA: %v\n", err)
			fmt.Printf("Initialize workload CA using\n\t`wl %s init`\n", workload)
			return
		}

		servicename := os.Args[4]
		err = certificates.ValidateSevriceName(servicename)
		if err != nil {
			fmt.Printf("Ilegal service name: %v\n", err)
			return
		}

		switch os.Args[3] {
		case "egg":
			wl_egg(workload, servicename)
			return
		case "cert":

			wl_cert(workload, servicename)
			return
		}
	case numArgs > 5:
		workload := os.Args[2]
		err = certificates.ValidateWorkloadName(workload)
		if err != nil {
			fmt.Printf("Ilegal workload name: %v\n", err)
			return
		}
		workloadCaKeyRing, err := certificates.GetCA(workload)
		if err != nil {
			fmt.Printf("Failed to load workload CA: %v\n", err)
			fmt.Printf("Initialize workload CA using\n\t`wl %s init`\n", workload)
			return
		}
		switch os.Args[3] {
		case "client":
			client := os.Args[4]
			err = certificates.ValidateSevriceName(client)
			if err != nil {
				fmt.Printf("Ilegal client service name: %v\n", err)
				return
			}
			if os.Args[5] != "servers" {
				wl_help()
				return
			}
			servers := []string(make([]string, 0))

			for i := 6; i < numArgs; i++ {
				server := os.Args[i]
				err = certificates.ValidateSevriceName(server)
				if err != nil {
					fmt.Printf("Ilegal server service name: %v\n", err)
					return
				}
				servers = append(servers, server)
			}

			wl_connect(workloadCaKeyRing, workload, client, servers)
			return
		}
	}
	wl_help()
}

func wl_help() {
	fmt.Printf("Control a Seal workload\n\n")
	fmt.Printf("Subcommands:\n\n")
	fmt.Printf("  seal wl\n")
	fmt.Printf("  seal wl <Workload-Name>\n")
	fmt.Printf("  seal wl <Workload-Name> del\n")
	fmt.Printf("  seal wl <Workload-Name> init\n")
	fmt.Printf("  seal wl <Workload-Name> egg\n")
	fmt.Printf("  seal wl <Workload-Name> cert\n")
	fmt.Printf("  seal wl <Workload-Name> egg <Name>\n")
	fmt.Printf("  seal wl <Workload-Name> cert <Name>\n")
	fmt.Printf("  seal wl <Workload-Name> client <Name> servers *[,<Name>]...\n")
}

func wl_connect(workloadCaKeyRing *certificates.KeyRing, workload string, client string, servers []string) {
	workloadCaKeyRing.AddPeer(client, strings.Join(servers, ","))

	err := certificates.UpdateCA(workload, workloadCaKeyRing)
	if err != nil {
		fmt.Printf("Failed to update secret: %w\n", err)
	}
}

func wl_init(workload string, rotUrl string) {
	if !certificates.CANotFound(workload) {
		fmt.Printf("Delete ROT CA first\n\t`wl %s del`\n", workload)
		return
	}
	fmt.Printf("Initializing workload `%s` CA Secret\n", workload)

	keyRing, err := certificates.CreateNewCA(workload, rotUrl)
	if err != nil {
		fmt.Printf("Failed to create a new workload CA: %v\n", err)
		return
	}

	fmt.Printf("Seal workload `%s`:\n", workload)
	fmt.Printf("  RotUrl:       %s\n", keyRing.RotUrl())
	fmt.Printf("  Certs:        %d\n", keyRing.NumCerts())
	fmt.Printf("  PrivateKeys:  %d\n", keyRing.NumPrivateKeys())
	fmt.Printf("  SymetricKeys: %d\n", keyRing.NumSymetricKeys())
}

func wl_del(workload string) {
	if certificates.CANotFound(workload) {
		fmt.Printf("Workload `%s` CA does not exist\n", workload)
		return
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
}
func wl_cert(workload string, servicename string) {
	pmr := certificates.NewPodMessageReq(workload, servicename)
	podMessage, err := certificates.CreatePodMessage(pmr)
	if err != nil {
		fmt.Printf("Failed to CreatePodMessage: %v\n", err)
		return
	}

	cas, err := podMessage.GetCaPem()
	if err != nil {
		fmt.Printf("Failed to get CA Pem: %v\n", err)
		return
	}
	cert, pkey, err := podMessage.GetCertPem()
	if err != nil {
		fmt.Printf("Failed to get Cert and Prk Pems: %v\n", err)
		return
	}

	err = toFile("ca.pem", cas)
	if err != nil {
		fmt.Printf("Failed creating CA PEM: %v\n", err)
		return
	}

	certificate, err := tls.X509KeyPair(cert, pkey)
	if err != nil {
		fmt.Printf("tls.X509KeyPair failed: %v", err)
		return
	}
	err = toFile("x509.cert", certificate.Certificate[0])
	if err != nil {
		fmt.Printf("Failed creating PRK PEM: %v\n", err)
		return
	}

	err = toFile("cert.pem", cert)
	if err != nil {
		fmt.Printf("Failed creating CERT PEM: %v\n", err)
		return
	}
	err = toFile("prk.pem", pkey)
	if err != nil {
		fmt.Printf("Failed creating PRK PEM: %v\n", err)
		return
	}
	fmt.Printf("ca.pem, cert.pem, prk.pem files created\n")

}

func toFile(filename string, data []byte) error {
	f, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("Failed to open file %s: %v", filename, err)
	}
	defer f.Close()

	_, err = f.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("Failed to write to file %s: %v", filename, err)
	}
	return nil
}

func wl_egg(workload string, servicename string) {
	egg, err := certificates.CreateInit(workload, servicename)
	if err != nil {
		fmt.Printf("Failed to create egg: %v\n", err)
		return
	}
	eegg, err := egg.Encode()
	if err != nil {
		fmt.Printf("Failed to encode egg: %v\n", err)
		return
	}
	fmt.Println(eegg)
}
