package secrets

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/rancher/shepherd/clients/rancher"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	clusterapi "github.com/rancher/tests/actions/kubeapi/clusters"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateCertificateSecret creates a TLS secret in Kubernetes
func CreateCertificateSecret(client *rancher.Client, clusterID, namespace string, secretData map[string][]byte, secretType corev1.SecretType) (*corev1.Secret, error) {
	log.Infof("Creating certificate secret %s in namespace %s", namegen.AppendRandomString("test"), namespace)

	clusterContext, err := clusterapi.GetClusterWranglerContext(client, clusterID)
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "tls-cert-",
			Namespace:    namespace,
		},
		Type: secretType,
		Data: secretData,
	}

	return clusterContext.Core.Secret().Create(secret)
}

// GenerateSelfSignedCert creates a new self-signed certificate and private key
func GenerateSelfSignedCert() (string, string, error) {
	log.Debug("Generating RSA private key")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Errorf("Failed to generate private key: %v", err)
		return "", "", err
	}

	log.Debug("Creating certificate template")
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Errorf("Failed to generate serial number: %v", err)
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Rancher Test CA"},
			CommonName:   "rancher.test.local",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"rancher.test.local", "localhost"},
	}

	log.Debug("Creating certificate")
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Errorf("Failed to create certificate: %v", err)
		return "", "", err
	}

	log.Debug("Encoding certificate to PEM format")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	log.Debug("Encoding private key to PEM format")
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	return string(certPEM), string(keyPEM), nil
}

// UpdateCertificateSecretData updates the data in a certificate secret
func UpdateCertificateSecretData(secret *corev1.Secret, newData map[string][]byte) *corev1.Secret {
	updatedSecret := secret.DeepCopy()

	if updatedSecret.Data == nil {
		updatedSecret.Data = make(map[string][]byte)
	}

	for k, v := range newData {
		updatedSecret.Data[k] = v
	}

	return updatedSecret
}
