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
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/davidhadas/seal-control/pkg/certificates"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes/scheme"
)

func apply(workloadCaKeyRing *certificates.KeyRing, args []string) {
	var infile, outfile string
	var sealall bool
	for {
		if len(args) == 0 {
			if infile != "" {
				apply_files(workloadCaKeyRing, infile, outfile, sealall)
			} else {
				apply_help()
			}
			return
		}
		switch args[0] {
		case "-f":
			if len(args) < 2 {
				apply_help()
				return
			}
			infile = args[1]
			args = args[2:]
		case "-o":
			if len(args) < 2 {
				apply_help()
				return
			}
			outfile = args[1]
			args = args[2:]
		case "-a":
			sealall = true
			args = args[1:]
		case "-h":
			apply_help()
			return
		default:
			apply_help()
			return
		}
	}
}

func apply_help() {
	fmt.Printf("Apply an encrypted configuration by file or stdin.\n")
	fmt.Printf("Supported resources include:\n")
	fmt.Printf("\tConfigMaps\n")
	fmt.Printf("\tSecrets\n")
	fmt.Printf("\tDeployments\n")

	fmt.Printf("\nFlags:\n\n")
	fmt.Printf(" -i <filepath> 		yaml file to read from, stdin by default\n")
	fmt.Printf(" -o <filepath> 		yaml file to write to, apply by default\n")
	fmt.Printf(" -a  				seal complete cm or se yaml \n")

	fmt.Printf("\nSubcommands:\n\n")
	fmt.Printf("  seal apply -f <cm.yaml>\n")
	fmt.Printf("  seal apply -f <cm.yaml> -o <encrtypted-cm.yaml>\n")
	fmt.Printf("  seal apply -f <cm.yaml> -o -a\n")
	fmt.Printf("  cat cm.yaml | seal apply -f -\n")
}

func apply_files(workloadCaKeyRing *certificates.KeyRing, infile string, outfile string, sealall bool) {
	var reader io.Reader
	if infile == "-" {
		reader = bufio.NewReader(os.Stdin)
	} else {
		file, err := os.Open(infile)
		if err != nil {
			fmt.Printf("Failed to open file: %v\n", err)
			return
		}
		defer file.Close()
		reader = file
	}
	reader = io.LimitReader(reader, 1e+5) // 100K bytes
	buf, err := io.ReadAll(reader)
	if err != nil {
		fmt.Printf("Failed to ReadAll: %v\n", err)
		return
	}
	bufSplits := strings.Split(string(buf), "---\n")
	for _, split := range bufSplits {
		apply_file(workloadCaKeyRing, []byte(split), outfile, sealall)
	}
}
func apply_file(workloadCaKeyRing *certificates.KeyRing, buf []byte, outfile string, sealall bool) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode(buf, nil, nil)
	if err != nil {
		fmt.Printf("Failed to decode: %v\n", err)
		return
	}
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	if outfile != "-" {
		fmt.Printf("Apply %s\n", kind)
	}
	switch kind {
	case "ConfigMap":
		cm := obj.(*v1.ConfigMap)
		sd := certificates.NewSealData()
		for key, val := range cm.Data {
			sd.AddUnsealed(key, []byte(val))
		}
		for key, val := range cm.BinaryData {
			sd.AddUnsealed(key, val)
		}
		err := sd.EncryptItems(workloadCaKeyRing.GetSymetricKey(), "")
		if err != nil {
			fmt.Printf("Failed to Encrypt: %v\n", err)
			return
		}
		cm.Data = make(map[string]string)
		cm.BinaryData = nil
		for k, v := range sd.SealedMap {
			cm.Data[k] = base64.StdEncoding.EncodeToString(v)
		}
		//cm.BinaryData = sd.SealedMap
		if outfile != "" {
			if err := outputFile(outfile, cm); err != nil {
				fmt.Printf("Failed to output Secret %v\n", err)
			}
		} else {
			if err := certificates.KubeMgr.SetConfigMap(cm); err != nil {
				fmt.Printf("Failed to SetCm %v\n", err)
			}
		}
	case "Secret":
		secret := obj.(*v1.Secret)
		sd := certificates.NewSealData()
		for key, val := range secret.Data {
			sd.AddUnsealed(key, val)
		}
		for key, val := range secret.StringData {
			sd.AddUnsealed(key, []byte(val))
		}
		switch secret.Type {
		case "kubernetes.io/dockerconfigjson",
			"kubernetes.io/dockercfg",
			"kubernetes.io/service-account-token":
			// do nothing
		default: // seal each item
			err := sd.EncryptItems(workloadCaKeyRing.GetSymetricKey(), "")
			if err != nil {
				fmt.Printf("Failed to Encrypt: %v\n", err)
				return
			}
			secret.StringData = make(map[string]string)
			secret.Data = nil
			for k, v := range sd.SealedMap {
				secret.StringData[k] = base64.StdEncoding.EncodeToString(v)
			}
		}
		if outfile != "" {
			if err := outputFile(outfile, secret); err != nil {
				fmt.Printf("Failed to output Secret %v\n", err)
			}
		} else {
			if err := certificates.KubeMgr.SetSecret(secret); err != nil {
				fmt.Printf("Failed to set Secret %v\n", err)
			}
		}
	case "Deployment":
		deployment := obj.(*appsv1.Deployment)
		for containerIndex, container := range deployment.Spec.Template.Spec.Containers {
			sdEnv := certificates.NewSealData()
			envVar := []v1.EnvVar{}
			for _, env := range container.Env {
				if env.ValueFrom == nil {
					sdEnv.AddUnsealed(env.Name, []byte(env.Value))
				} else {
					envVar = append(envVar, env)
				}
			}
			err := sdEnv.EncryptItems(workloadCaKeyRing.GetSymetricKey(), "")
			if err != nil {
				fmt.Printf("Failed to Encrypt Env: %v\n", err)
				return
			}
			for k, v := range sdEnv.SealedMap {
				envVar = append(envVar, v1.EnvVar{Name: k, Value: base64.StdEncoding.EncodeToString(v)})
			}
			deployment.Spec.Template.Spec.Containers[containerIndex].Env = envVar

			if len(container.Command) < 1 {
				fmt.Printf("Missing madatory Command in container: %s\n", container.Name)
				return
			}
			sdArgs := certificates.NewSealData()
			index := 0
			for _, arg := range container.Command {
				sdArgs.AddUnsealed(strconv.Itoa(index), []byte(arg))
				index++
			}

			for _, arg := range container.Args {
				sdArgs.AddUnsealed(strconv.Itoa(index), []byte(arg))
				index++
			}
			sealedArgs, err := sdArgs.Encrypt(workloadCaKeyRing.GetSymetricKey(), "args")
			if err != nil {
				fmt.Printf("Failed to Encrypt Args: %v\n", err)
				return
			}
			base64Sealed := base64.StdEncoding.EncodeToString(sealedArgs)
			deployment.Spec.Template.Spec.Containers[containerIndex].Args = []string{base64Sealed}
			deployment.Spec.Template.Spec.Containers[containerIndex].Command = []string{"seal-wrap"}
		}
		if outfile != "" {
			if err := outputFile(outfile, deployment); err != nil {
				fmt.Printf("Failed to output Secret %v\n", err)
			}
		} else {
			if err := certificates.KubeMgr.SetDeployment(deployment); err != nil {
				fmt.Printf("Failed to SetDeployment %v\n", err)
			}
		}
	default:
		fmt.Printf("Skipping ilegal kind %s\n", kind)
		return
	}
}

func outputFile(outfile string, obj runtime.Object) error {
	var out *os.File
	y := printers.YAMLPrinter{}

	if outfile == "-" {
		out = os.Stdout
	} else {
		// write to file
		out, err := os.Create(outfile)
		if err != nil {
			return fmt.Errorf("Failed to create file %v", err)
		}
		defer out.Close()
	}

	err := y.PrintObj(obj, out)
	if err != nil {
		return fmt.Errorf("Failed to write to file %v", err)
	}
	os.Stdout.WriteString("---\n")
	return nil
}
