/*
Copyright 2023 The Knative Authors

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

package certificates

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var KubeMgr *KubeMgrStruct

const (
	sealCtrlNamespace = "seal-control"
)

type KubeMgrStruct struct {
	client            *kubernetes.Clientset
	sealCtrlNamespace string
	RotCaKeyRing      *KeyRing
}

func LoadRotCa() error {
	var err error
	KubeMgr.RotCaKeyRing, err = GetCA("")
	return err
}

func InitKubeMgr() error {
	var err error
	KubeMgr = &KubeMgrStruct{
		sealCtrlNamespace: sealCtrlNamespace,
	}

	var kubeCfg *rest.Config
	var devKubeConfigStr *string

	// Try to detect in-cluster config
	if kubeCfg, err = rest.InClusterConfig(); err != nil {
		// Not running in cluster
		if home := homedir.HomeDir(); home != "" {
			devKubeConfigStr = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			devKubeConfigStr = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()

		// Use the current context in kubeconfig
		if kubeCfg, err = clientcmd.BuildConfigFromFlags("", *devKubeConfigStr); err != nil {
			return fmt.Errorf("No Config found to access KubeApi! err: %w\n", err)
		}
	}

	// Create a secrets client
	KubeMgr.client, err = kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return fmt.Errorf("Failed to configure KubeApi using config: %w\n", err)
	}
	return nil
}

func (kubeMgr *KubeMgrStruct) GetCa(workloadName string) (*v1.Secret, error) {
	var err error
	workloadName, err = processWorkloadname(workloadName)
	if err != nil {
		return nil, fmt.Errorf("Cant Get CA: %w ", err)
	}
	if len(workloadName) > 63 {
		return nil, errors.New("workloadName too long")
	}
	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	return secrets.Get(context.Background(), workloadName, metav1.GetOptions{})
}

func (kubeMgr *KubeMgrStruct) DeleteCa(workloadName string) error {
	var err error
	workloadName, err = processWorkloadname(workloadName)
	if err != nil {
		return fmt.Errorf("Cant Delete CA: %w ", err)
	}
	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	secrets.Delete(context.Background(), workloadName, metav1.DeleteOptions{})
	return nil
}

func (kubeMgr *KubeMgrStruct) CreateCa(workloadName string) (*v1.Secret, error) {
	var err error
	workloadName, err = processWorkloadname(workloadName)
	if err != nil {
		return nil, fmt.Errorf("Cant Delete CA: %w ", err)
	}
	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	s := corev1.Secret{}
	s.Name = workloadName
	s.Namespace = kubeMgr.sealCtrlNamespace
	s.Data = map[string][]byte{}
	return secrets.Create(context.Background(), &s, metav1.CreateOptions{})
}

func (kubeMgr *KubeMgrStruct) UpdateCA(secret *v1.Secret) (*v1.Secret, error) {
	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	return secrets.Update(context.Background(), secret, metav1.UpdateOptions{})
}

func (kubeMgr *KubeMgrStruct) ListCas() ([]string, error) {
	result := make([]string, 0)

	secrets := kubeMgr.client.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	list, err := secrets.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return result, err
	}
	for _, secret := range list.Items {
		name := secret.Name
		if strings.HasPrefix(name, "wl-") && len(name) > 3 {
			result = append(result, secret.Name[3:])
		}
	}
	return result, nil
}
