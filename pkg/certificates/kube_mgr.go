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

package certificates

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	rotClient         *kubernetes.Clientset
	sealCtrlNamespace string
	RotCaKeyRing      *KeyRing
}

type KubeMgrError struct {
	Value       int
	Description string
}

const (
	KmeUnknown      = 0
	KmeUnauthorized = 1
	KmeNoAccess     = 2
)

func (kme *KubeMgrError) Error() string {
	return fmt.Sprintf("value error: %s", kme.Description)
}

func LoadRotCa() error {
	var err error
	KubeMgr.RotCaKeyRing, err = GetCA("")
	return err
}

func InitRotKubeMgr() error {
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
			return fmt.Errorf("no Config found to access KubeApi! err: %w", err)
		}
	}

	// Create a secrets client
	KubeMgr.rotClient, err = kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return fmt.Errorf("failed to configure KubeApi using config: %w", err)
	}
	return nil
}

func InitRemoteKubeMgr(contextName string) (*kubernetes.Clientset, error) {
	var err error
	var kubeCfg *rest.Config

	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{
		CurrentContext: contextName,
	}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides)
	kubeCfg, err = clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get complete client config for context %s: %w", contextName, err)
	}

	// Create a secrets client
	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to configure KubeApi using config for context %s: %w", contextName, err)
	}
	return client, nil
}

func (kubeMgr *KubeMgrStruct) GetCa(workloadName string) (*corev1.Secret, error) {
	var err error
	workloadName, err = processWorkloadname(workloadName)
	if err != nil {
		return nil, fmt.Errorf("cant Get CA: %w ", err)
	}
	if len(workloadName) > 63 {
		return nil, errors.New("workloadName too long")
	}
	secrets := kubeMgr.rotClient.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	return secrets.Get(context.Background(), workloadName, metav1.GetOptions{})
}

func (kubeMgr *KubeMgrStruct) DeleteCa(workloadName string) error {
	var err error
	workloadName, err = processWorkloadname(workloadName)
	if err != nil {
		return fmt.Errorf("cant Delete CA: %w ", err)
	}
	secrets := kubeMgr.rotClient.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	secrets.Delete(context.Background(), workloadName, metav1.DeleteOptions{})
	return nil
}

func (kubeMgr *KubeMgrStruct) CreateCa(workloadName string) (*corev1.Secret, error) {
	var err error
	workloadName, err = processWorkloadname(workloadName)
	if err != nil {
		return nil, fmt.Errorf("cant Delete CA: %w ", err)
	}
	secrets := kubeMgr.rotClient.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	s := corev1.Secret{}
	s.Name = workloadName
	s.Namespace = kubeMgr.sealCtrlNamespace
	s.Data = map[string][]byte{}
	return secrets.Create(context.Background(), &s, metav1.CreateOptions{})
}

func (kubeMgr *KubeMgrStruct) UpdateCA(secret *corev1.Secret) (*corev1.Secret, error) {
	secrets := kubeMgr.rotClient.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
	return secrets.Update(context.Background(), secret, metav1.UpdateOptions{})
}

/*
func (kubeMgr *KubeMgrStruct) ApplySecret(secret *acorev1.SecretApplyConfiguration) (*corev1.Secret, error) {
	secrets := kubeMgr.rotClient.CoreV1().Secrets(*secret.Namespace)
	return secrets.Apply(context.Background(), secret, metav1.ApplyOptions{FieldManager: "application/apply-patch"})
}
*/

func (kubeMgr *KubeMgrStruct) SetDeployment(client *kubernetes.Clientset, deployment *appsv1.Deployment) error {
	if deployment.Namespace == "" {
		deployment.Namespace = "default"
	}
	deployments := client.AppsV1().Deployments(deployment.Namespace)
	_, err := deployments.Get(context.Background(), deployment.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = deployments.Create(context.Background(), deployment, metav1.CreateOptions{FieldManager: "seal"})
			if err != nil {
				return fmt.Errorf("failed to create deployment: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to get deployment %w", err)
	}
	_, err = deployments.Update(context.Background(), deployment, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update deployment: %w", err)
	}
	return nil
}

func (kubeMgr *KubeMgrStruct) SetSecret(client *kubernetes.Clientset, secret *corev1.Secret) error {
	if secret.Namespace == "" {
		secret.Namespace = "default"
	}
	secrets := client.CoreV1().Secrets(secret.Namespace)
	_, err := secrets.Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = secrets.Create(context.Background(), secret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create secret: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to get secret %w", err)
	}
	_, err = secrets.Update(context.Background(), secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}
	return nil
}

func (kubeMgr *KubeMgrStruct) SetConfigMap(client *kubernetes.Clientset, configmap *corev1.ConfigMap) error {
	if configmap.Namespace == "" {
		configmap.Namespace = "default"
	}
	configmaps := client.CoreV1().ConfigMaps(configmap.Namespace)
	_, err := configmaps.Get(context.Background(), configmap.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = configmaps.Create(context.Background(), configmap, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create configmap: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to get configmap %w", err)
	}
	_, err = configmaps.Update(context.Background(), configmap, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update configmap: %w", err)
	}
	return nil
}

/*
	func (kubeMgr *KubeMgrStruct) ApplyCm(cm *acorev1.ConfigMapApplyConfiguration) (*corev1.ConfigMap, error) {
		cms := kubeMgr.rotClient.CoreV1().ConfigMaps(*cm.Namespace)
		return cms.Apply(context.Background(), cm, metav1.ApplyOptions{FieldManager: "application/apply-patch"})
	}
*/

func (kubeMgr *KubeMgrStruct) ListCas() ([]string, error) {
	result := make([]string, 0)

	secrets := kubeMgr.rotClient.CoreV1().Secrets(kubeMgr.sealCtrlNamespace)
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
