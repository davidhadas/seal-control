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
	"crypto/tls"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/davidhadas/vault-control/pkg/certificates"
	"github.com/davidhadas/vault-control/pkg/vaultlog"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
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
			fmt.Printf("No Config found to access KubeApi! err: %v\n", err)
			return
		}
	}

	// Create a secrets client
	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		fmt.Printf("Failed to configure KubeAPi using config: %v\n", err)
		return
	}

	secrets := client.CoreV1().Secrets("knative-serving")

	// Certificate Authority
	caSecret, err := secrets.Get(context.Background(), "serving-certs-ctrl-ca", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		fmt.Printf("knative-serving-certs secret is missing - lets create it\n")

		s := corev1.Secret{}
		s.Name = "serving-certs-ctrl-ca"
		s.Namespace = "knative-serving"
		s.Data = map[string][]byte{}
		caSecret, err = secrets.Create(context.Background(), &s, metav1.CreateOptions{})
	}
	if err != nil {
		fmt.Printf("Error accessing serving-certs-ctrl-ca secret: %v\n", err)
		return
	}
	caCert, caPk, err := parseAndValidateSecret(caSecret, false)
	if err != nil {
		fmt.Printf("serving-certs-ctrl-ca secret is missing the required keypair - lets add it\n")

		// We need to generate a new CA cert, then shortcircuit the reconciler
		keyPair, err := certificates.CreateCACerts(caExpirationInterval)
		if err != nil {
			fmt.Printf("Cannot generate the keypair for the serving-certs-ctrl-ca secret: %v\n", err)
			return
		}
		err = commitUpdatedSecret(client, caSecret, keyPair, nil)
		if err != nil {
			fmt.Printf("Failed to commit the keypair for the serving-certs-ctrl-ca secret: %v\n", err)
			return
		}
		caCert, caPk, err = parseAndValidateSecret(caSecret, false)
		if err != nil {
			fmt.Printf("Failed while validating keypair for serving-certs-ctrl-ca : %v\n", err)
			return
		}
	}
	fmt.Printf("Done processing serving-certs-ctrl-ca secret\n")

	// Current Keys
	secret, err := secrets.Get(context.Background(), "knative-serving-certs", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		fmt.Printf("knative-serving-certs secret is missing - lets create it\n")

		s := corev1.Secret{}
		s.Name = "knative-serving-certs"
		s.Namespace = "knative-serving"
		s.Data = map[string][]byte{}
		secret, err = secrets.Create(context.Background(), &s, metav1.CreateOptions{})
	}
	if err != nil {
		fmt.Printf("Error accessing knative-serving-certs secret: %v\n", err)
		return
	}

	// Reconcile the provided secret
	_, _, err = parseAndValidateSecret(secret, true)
	if err != nil {
		fmt.Printf("knative-serving-certs secret is missing the required keypair - lets add it\n")

		// Check the secret to reconcile type
		var keyPair *certificates.KeyPair

		keyPair, err = certificates.CreateDataPlaneCert(ctx, caPk, caCert, expirationInterval)
		if err != nil {
			fmt.Printf("Cannot generate the keypair for the knative-serving-certs secret: %v\n", err)
			return
		}
		err = commitUpdatedSecret(client, secret, keyPair, caSecret.Data[certificates.SecretCertKey])
		if err != nil {
			fmt.Printf("Failed to commit the keypair for the knative-serving-certs secret: %v\n", err)
			return
		}
		_, _, err = certificates.ParseCert(keyPair.CertBytes(), keyPair.PrivateKeyBytes())
		if err != nil {
			fmt.Printf("Failed while validating keypair for knative-serving-certs secret: %v\n", err)
			return
		}
	}
	fmt.Printf("Done processing knative-serving-certs secret\n")

	// create a Certificate Athority
	caExpirationInterval := time.Hour * 24 * 365 * 10 // 10 years
	caKeyPair, err := certificates.CreateCACerts(caExpirationInterval)
	if err != nil {
		logger.Fatal("webhook  certificates.CreateCACerts failed", err)
	}
	sans := []string{"guard-webhook.knative-serving.svc"}
	caCert, caPk, err := certificates.ParseCert(caKeyPair.CertBytes(), caKeyPair.PrivateKeyBytes())
	if err != nil {
		logger.Fatal("webhook  certificates.ParseCert failed", err)
	}

	expirationInterval := time.Hour * 24 * 30 // 30 days
	keyPair, err := certificates.CreateCert(caPk, caCert, expirationInterval, sans...)
	if err != nil {
		logger.Fatal("webhook  certificates.CreateCert failed", err)
	}
	serverCert, err := tls.X509KeyPair(keyPair.CertBytes(), keyPair.PrivateKeyBytes())
	if err != nil {
		logger.Fatal("webhook  tls.X509KeyPair failed", err)
	}
}
