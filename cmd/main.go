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
	"context"
	"flag"
	"path/filepath"
	"time"

	"github.com/davidhadas/vault-control/pkg/certificates"
	"github.com/davidhadas/vault-control/pkg/vaultlog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	vaultlog.InitLog()
	logger := vaultlog.Log

	var err error
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
			logger.Infof("No Config found to access KubeApi! err: %v\n", err)
			return
		}
	}

	// Create a secrets client
	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		logger.Infof("Failed to configure KubeAPi using config: %v\n", err)
		return
	}

	secrets := client.CoreV1().Secrets("knative-serving")

	// Certificate Authority
	caSecret, err := secrets.Get(context.Background(), "serving-certs-ctrl-ca", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		logger.Infof("knative-serving-certs secret is missing - lets create it\n")

		s := corev1.Secret{}
		s.Name = "serving-certs-ctrl-ca"
		s.Namespace = "knative-serving"
		s.Data = map[string][]byte{}
		caSecret, err = secrets.Create(context.Background(), &s, metav1.CreateOptions{})
	}
	if err != nil {
		logger.Infof("Error accessing serving-certs-ctrl-ca secret: %v\n", err)
		return
	}
	caCert, caPk, err := certificates.ParseAndValidateSecret(caSecret, false)
	if err != nil {
		logger.Infof("serving-certs-ctrl-ca secret is missing the required keypair - lets add it\n")

		// We need to generate a new CA cert, then shortcircuit the reconciler
		caExpirationInterval := time.Hour * 24 * 365 * 10 // 10 years
		keyPair, err := certificates.CreateCACerts(caExpirationInterval)
		if err != nil {
			logger.Infof("Cannot generate the keypair for the serving-certs-ctrl-ca secret: %v\n", err)
			return
		}
		err = certificates.CommitUpdatedSecret(client, caSecret, keyPair, nil)
		if err != nil {
			logger.Infof("Failed to commit the keypair for the serving-certs-ctrl-ca secret: %v\n", err)
			return
		}
		caCert, caPk, err = certificates.ParseAndValidateSecret(caSecret, false)
		if err != nil {
			logger.Infof("Failed while validating keypair for serving-certs-ctrl-ca : %v\n", err)
			return
		}
	}
	logger.Infof("Done processing serving-certs-ctrl-ca secret\n")

	// Current Keys
	secret, err := secrets.Get(context.Background(), "knative-serving-certs", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		logger.Infof("knative-serving-certs secret is missing - lets create it\n")

		s := corev1.Secret{}
		s.Name = "knative-serving-certs"
		s.Namespace = "knative-serving"
		s.Data = map[string][]byte{}
		secret, err = secrets.Create(context.Background(), &s, metav1.CreateOptions{})
	}
	if err != nil {
		logger.Infof("Error accessing knative-serving-certs secret: %v\n", err)
		return
	}

	// Reconcile the provided secret
	_, _, err = certificates.ParseAndValidateSecret(secret, true)
	if err != nil {
		logger.Infof("knative-serving-certs secret is missing the required keypair - lets add it\n")

		// Check the secret to reconcile type
		var keyPair *certificates.KeyPair

		expirationInterval := time.Hour * 24 * 30 // 30 days
		sans := []string{"guard-webhook.knative-serving.svc"}
		keyPair, err = certificates.CreateCert(caPk, caCert, expirationInterval, sans...)
		if err != nil {
			logger.Infof("Cannot generate the keypair for the knative-serving-certs secret: %v\n", err)
			return
		}
		err = certificates.CommitUpdatedSecret(client, secret, keyPair, caSecret.Data[certificates.PrivateKeyName])
		if err != nil {
			logger.Infof("Failed to commit the keypair for the knative-serving-certs secret: %v\n", err)
			return
		}
		_, _, err = certificates.ParseCert(keyPair.CertBytes(), keyPair.PrivateKeyBytes())
		if err != nil {
			logger.Infof("Failed while validating keypair for knative-serving-certs secret: %v\n", err)
			return
		}
	}
	logger.Infof("Done processing knative-serving-certs secret\n")
}
