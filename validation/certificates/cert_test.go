//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress

package certificate

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/rancher/shepherd/pkg/session"
	clusterapi "github.com/rancher/tests/actions/kubeapi/clusters"
	"github.com/rancher/tests/actions/kubeapi/ingresses"
	"github.com/rancher/tests/actions/projects"
	"github.com/rancher/tests/actions/rbac"
	"github.com/rancher/tests/actions/secrets"
	"github.com/rancher/tests/actions/workloads/deployment"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testImage = "rancher/nginx-ingress-controller:nginx-0.47.0-rancher1"
	testPort  = 80
)

type CertificateTestSuite struct {
	suite.Suite
	client    *rancher.Client
	session   *session.Session
	cluster   *management.Cluster
	certData1 string
	keyData1  string
	certData2 string
	keyData2  string
}

func (c *CertificateTestSuite) SetupSuite() {
	c.session = session.NewSession()

	client, err := rancher.NewClient("", c.session)
	assert.NoError(c.T(), err)
	c.client = client

	log.Info("Getting cluster name from the config file")
	clusterName := client.RancherConfig.ClusterName
	require.NotEmptyf(c.T(), clusterName, "Cluster name should be set")

	clusterID, err := clusters.GetClusterIDByName(c.client, clusterName)
	require.NoError(c.T(), err, "Error getting cluster ID")

	c.cluster, err = c.client.Management.Cluster.ByID(clusterID)
	assert.NoError(c.T(), err)

	log.Info("Generating first self-signed certificate and key for certificate operations")
	c.certData1, c.keyData1, err = secrets.GenerateSelfSignedCert()
	assert.NoError(c.T(), err)

	log.Info("Generating second self-signed certificate and key for certificate operations")
	c.certData2, c.keyData2, err = secrets.GenerateSelfSignedCert()
	assert.NoError(c.T(), err)

	log.Info("Certificates generated successfully")
}

func (c *CertificateTestSuite) TearDownSuite() {
	c.session.Cleanup()
}

func (c *CertificateTestSuite) TestCertificateScopes() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating a certificate in the namespace")
	secretData := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	nsSecret, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Verifying the certificate exists in the namespace")
	adminContext, err := clusterapi.GetClusterWranglerContext(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	retrievedSecret, err := adminContext.Core.Secret().Get(namespace.Name, nsSecret.Name, metav1.GetOptions{})
	assert.NoError(c.T(), err)
	assert.Equal(c.T(), corev1.SecretTypeTLS, retrievedSecret.Type)

	log.Info("Creating a second namespace")
	_, namespace2, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Verifying the certificate is not accessible in the second namespace")
	_, err = adminContext.Core.Secret().Get(namespace2.Name, nsSecret.Name, metav1.GetOptions{})
	assert.Error(c.T(), err)
}

func (c *CertificateTestSuite) TestMultipleCertificateTypes() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating first certificate")
	secretData1 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert1, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData1, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating second certificate")
	secretData2 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData2),
		corev1.TLSPrivateKeyKey: []byte(c.keyData2),
	}
	cert2, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData2, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Verifying both certificates were created successfully")
	adminContext, err := clusterapi.GetClusterWranglerContext(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	retrievedCert1, err := adminContext.Core.Secret().Get(namespace.Name, cert1.Name, metav1.GetOptions{})
	assert.NoError(c.T(), err)
	assert.Equal(c.T(), corev1.SecretTypeTLS, retrievedCert1.Type)

	retrievedCert2, err := adminContext.Core.Secret().Get(namespace.Name, cert2.Name, metav1.GetOptions{})
	assert.NoError(c.T(), err)
	assert.Equal(c.T(), corev1.SecretTypeTLS, retrievedCert2.Type)
}

func (c *CertificateTestSuite) TestUpdateCertificate() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate")
	secretData1 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData1, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Getting the certificate for updating")
	adminContext, err := clusterapi.GetClusterWranglerContext(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	retrievedSecret, err := adminContext.Core.Secret().Get(namespace.Name, cert.Name, metav1.GetOptions{})
	assert.NoError(c.T(), err)

	log.Info("Updating the certificate with new data")
	secretData2 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData2),
		corev1.TLSPrivateKeyKey: []byte(c.keyData2),
	}

	updatedSecret := retrievedSecret.DeepCopy()
	updatedSecret.Data = secretData2

	_, err = adminContext.Core.Secret().Update(updatedSecret)
	assert.NoError(c.T(), err)

	log.Info("Verifying the certificate was updated")
	retrievedUpdatedSecret, err := adminContext.Core.Secret().Get(namespace.Name, cert.Name, metav1.GetOptions{})
	assert.NoError(c.T(), err)

	assert.Equal(c.T(), secretData2[corev1.TLSCertKey], retrievedUpdatedSecret.Data[corev1.TLSCertKey])
	assert.Equal(c.T(), secretData2[corev1.TLSPrivateKeyKey], retrievedUpdatedSecret.Data[corev1.TLSPrivateKeyKey])
}

func (c *CertificateTestSuite) TestCrossProjectAccess() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating first project and namespace")
	_, namespace1, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating second project and namespace")
	project2, _, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate in project 1")
	secretData := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	project1Secret, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace1.Name, secretData, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating user with access to project 2 only")
	user, userClient, err := rbac.AddUserWithRoleToCluster(c.client, rbac.StandardUser.String(), rbac.ProjectOwner.String(), c.cluster, project2)
	assert.NoError(c.T(), err)
	log.Infof("Created user: %v", user.Username)

	log.Info("Attempting to access project 1 certificate with project 2 user")
	userContext, err := clusterapi.GetClusterWranglerContext(userClient, c.cluster.ID)
	assert.NoError(c.T(), err)

	_, err = userContext.Core.Secret().Get(namespace1.Name, project1Secret.Name, metav1.GetOptions{})
	assert.True(c.T(), errors.IsForbidden(err), "User should not be able to access certificates in another project")
	log.Info("Verified user with access to project 2 cannot access certificates in project 1")
}

// Test using certificate with ingress in a single namespace
func (c *CertificateTestSuite) TestCertificateWithIngressSingleNS() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate in the namespace")
	secretData := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating deployment")
	deploymentForIngress, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating service and ingress template")
	ingressTemplate, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deploymentForIngress)
	assert.NoError(c.T(), err)

	ingressTemplate.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"test.example.com"},
			SecretName: cert.Name,
		},
	}

	log.Info("Creating ingress with certificate")
	ingress, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate.Name, namespace.Name, &ingressTemplate.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress)

	assert.Len(c.T(), ingress.Spec.TLS, 1)
	assert.Equal(c.T(), cert.Name, ingress.Spec.TLS[0].SecretName)
	log.Info("Successfully created and validated ingress with certificate in single namespace")
}

// Test using certificate with ingress across namespaces
func (c *CertificateTestSuite) TestCertificateWithIngressMultiNS() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating first project and namespace")
	_, namespace1, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating second namespace in same project")
	_, namespace2, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating first certificate")
	secretData1 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert1, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace1.Name, secretData1, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating second certificate")
	secretData2 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData2),
		corev1.TLSPrivateKeyKey: []byte(c.keyData2),
	}
	cert2, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace2.Name, secretData2, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating first deployment")
	deployment1, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace1.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating second deployment")
	deployment2, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace2.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating first service and ingress template")
	ingressTemplate1, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace1.Name, deployment1)
	assert.NoError(c.T(), err)

	log.Info("Creating second service and ingress template")
	ingressTemplate2, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace2.Name, deployment2)
	assert.NoError(c.T(), err)

	ingressTemplate1.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"test1.example.com"},
			SecretName: cert1.Name,
		},
	}

	ingressTemplate2.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"test2.example.com"},
			SecretName: cert2.Name,
		},
	}

	log.Info("Creating first ingress with certificate")
	ingress1, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate1.Name, namespace1.Name, &ingressTemplate1.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress1)

	log.Info("Creating second ingress with certificate")
	ingress2, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate2.Name, namespace2.Name, &ingressTemplate2.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress2)

	assert.Len(c.T(), ingress1.Spec.TLS, 1)
	assert.Equal(c.T(), cert1.Name, ingress1.Spec.TLS[0].SecretName)
	assert.Len(c.T(), ingress2.Spec.TLS, 1)
	assert.Equal(c.T(), cert2.Name, ingress2.Spec.TLS[0].SecretName)

	log.Info("Successfully created and validated ingresses with certificates in multiple namespaces")
}

func (c *CertificateTestSuite) TestUpdateCertificateWithIngress() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate")
	secretData1 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData1, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating deployment")
	deploymentForIngress, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating service and ingress template")
	ingressTemplate, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deploymentForIngress)
	assert.NoError(c.T(), err)

	ingressTemplate.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"test.example.com"},
			SecretName: cert.Name,
		},
	}

	log.Info("Creating ingress with certificate")
	ingress, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate.Name, namespace.Name, &ingressTemplate.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress)

	log.Info("Updating the certificate")
	adminContext, err := clusterapi.GetClusterWranglerContext(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	retrievedSecret, err := adminContext.Core.Secret().Get(namespace.Name, cert.Name, metav1.GetOptions{})
	assert.NoError(c.T(), err)

	secretData2 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData2),
		corev1.TLSPrivateKeyKey: []byte(c.keyData2),
	}

	updatedSecret := retrievedSecret.DeepCopy()
	updatedSecret.Data = secretData2

	_, err = adminContext.Core.Secret().Update(updatedSecret)
	assert.NoError(c.T(), err)

	ingressList, err := ingresses.ListIngresses(c.client, c.cluster.ID, namespace.Name, metav1.ListOptions{})
	assert.NoError(c.T(), err)
	assert.NotEmpty(c.T(), ingressList.Items)

	found := false
	for _, ing := range ingressList.Items {
		if ing.Name == ingress.Name {
			found = true
			assert.Len(c.T(), ing.Spec.TLS, 1)
			assert.Equal(c.T(), cert.Name, ing.Spec.TLS[0].SecretName)
			break
		}
	}
	assert.True(c.T(), found, "Ingress should be found in the list")

	log.Info("Successfully verified updated certificate still used by ingress")
}

func (c *CertificateTestSuite) TestSharedCertificateBetweenIngresses() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate")
	secretData := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating first deployment")
	deployment1, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "app1", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating second deployment")
	deployment2, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "app2", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating first service and ingress template")
	ingressTemplate1, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deployment1)
	assert.NoError(c.T(), err)

	log.Info("Creating second service and ingress template")
	ingressTemplate2, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deployment2)
	assert.NoError(c.T(), err)

	hostTLS := []netv1.IngressTLS{
		{
			Hosts:      []string{"shared.example.com"},
			SecretName: cert.Name,
		},
	}

	ingressTemplate1.Spec.TLS = hostTLS
	ingressTemplate2.Spec.TLS = hostTLS

	log.Info("Creating first ingress with certificate")
	ingress1, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate1.Name, namespace.Name, &ingressTemplate1.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress1)

	log.Info("Creating second ingress with same certificate")
	ingress2, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate2.Name, namespace.Name, &ingressTemplate2.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress2)

	log.Info("Verify both ingresses use the same certificate")
	assert.Len(c.T(), ingress1.Spec.TLS, 1)
	assert.Equal(c.T(), cert.Name, ingress1.Spec.TLS[0].SecretName)

	assert.Len(c.T(), ingress2.Spec.TLS, 1)
	assert.Equal(c.T(), cert.Name, ingress2.Spec.TLS[0].SecretName)

	log.Info("Successfully shared certificate between multiple ingresses")
}

func (c *CertificateTestSuite) TestDeleteCertificateUsedByIngress() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate")
	secretData := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating deployment")
	deploymentForIngress, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating service and ingress template")
	ingressTemplate, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deploymentForIngress)
	assert.NoError(c.T(), err)

	ingressTemplate.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"test.example.com"},
			SecretName: cert.Name,
		},
	}

	log.Info("Creating ingress with certificate")
	ingress, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate.Name, namespace.Name, &ingressTemplate.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress)

	log.Info("Deleting the certificate")
	adminContext, err := clusterapi.GetClusterWranglerContext(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	err = adminContext.Core.Secret().Delete(namespace.Name, cert.Name, &metav1.DeleteOptions{})
	assert.NoError(c.T(), err)

	ingressList, err := ingresses.ListIngresses(c.client, c.cluster.ID, namespace.Name, metav1.ListOptions{})
	assert.NoError(c.T(), err)
	assert.NotEmpty(c.T(), ingressList.Items)

	found := false
	for _, ing := range ingressList.Items {
		if ing.Name == ingress.Name {
			found = true
			assert.Len(c.T(), ing.Spec.TLS, 1)
			assert.Equal(c.T(), cert.Name, ing.Spec.TLS[0].SecretName)
			break
		}
	}
	assert.True(c.T(), found, "Ingress should still exist after certificate deletion")

	_, err = adminContext.Core.Secret().Get(namespace.Name, cert.Name, metav1.GetOptions{})
	assert.True(c.T(), errors.IsNotFound(err), "Certificate should be deleted")
	log.Info("Successfully verified ingress behavior after certificate deletion")
}

// Test certificate with multiple hosts in TLS configuration
func (c *CertificateTestSuite) TestCertificateWithMultipleHosts() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate")
	secretData := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	cert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating deployment")
	deploymentForIngress, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating service and ingress template")
	ingressTemplate, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deploymentForIngress)
	assert.NoError(c.T(), err)

	ingressTemplate.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"test1.example.com", "test2.example.com", "test3.example.com"},
			SecretName: cert.Name,
		},
	}

	log.Info("Creating ingress with certificate for multiple hosts")
	ingress, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate.Name, namespace.Name, &ingressTemplate.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress)

	assert.Len(c.T(), ingress.Spec.TLS, 1)
	assert.Equal(c.T(), cert.Name, ingress.Spec.TLS[0].SecretName)
	assert.Len(c.T(), ingress.Spec.TLS[0].Hosts, 3)
	assert.Contains(c.T(), ingress.Spec.TLS[0].Hosts, "test1.example.com")
	assert.Contains(c.T(), ingress.Spec.TLS[0].Hosts, "test2.example.com")
	assert.Contains(c.T(), ingress.Spec.TLS[0].Hosts, "test3.example.com")

	log.Info("Successfully created and validated ingress with certificate for multiple hosts")
}

func (c *CertificateTestSuite) TestCertificateWithAnnotations() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating certificate with annotations")

	adminContext, err := clusterapi.GetClusterWranglerContext(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	secretData := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cert-with-annotations-",
			Namespace:    namespace.Name,
			Annotations: map[string]string{
				"cert-manager.io/issuer":      "test-issuer",
				"cert-manager.io/issuer-kind": "ClusterIssuer",
				"custom-annotation":           "test-value",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: secretData,
	}

	createdSecret, err := adminContext.Core.Secret().Create(secret)
	assert.NoError(c.T(), err)

	retrievedSecret, err := adminContext.Core.Secret().Get(namespace.Name, createdSecret.Name, metav1.GetOptions{})
	assert.NoError(c.T(), err)
	assert.Equal(c.T(), "test-issuer", retrievedSecret.Annotations["cert-manager.io/issuer"])
	assert.Equal(c.T(), "ClusterIssuer", retrievedSecret.Annotations["cert-manager.io/issuer-kind"])
	assert.Equal(c.T(), "test-value", retrievedSecret.Annotations["custom-annotation"])

	log.Info("Creating deployment")
	deploymentForIngress, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating service and ingress template")
	ingressTemplate, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deploymentForIngress)
	assert.NoError(c.T(), err)

	ingressTemplate.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"test.example.com"},
			SecretName: createdSecret.Name,
		},
	}

	log.Info("Creating ingress with annotated certificate")
	ingress, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate.Name, namespace.Name, &ingressTemplate.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress)

	log.Info("Successfully created and validated certificate with annotations")
}

// Test certificate rotation by replacing a certificate used by an ingress
func (c *CertificateTestSuite) TestCertificateRotation() {
	subSession := c.session.NewSession()
	defer subSession.Cleanup()

	log.Info("Creating project and namespace")
	_, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(c.client, c.cluster.ID)
	assert.NoError(c.T(), err)

	log.Info("Creating original certificate")
	secretData1 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData1),
		corev1.TLSPrivateKeyKey: []byte(c.keyData1),
	}
	origCert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData1, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Creating deployment")
	deploymentForIngress, err := deployment.CreateDeployment(c.client, c.cluster.ID, namespace.Name, 1, "", "", false, false, false, true)
	assert.NoError(c.T(), err)

	log.Info("Creating service and ingress template")
	ingressTemplate, err := ingresses.CreateServiceAndIngressTemplateForDeployment(c.client, c.cluster.ID, namespace.Name, deploymentForIngress)
	assert.NoError(c.T(), err)

	ingressTemplate.Spec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"rotate.example.com"},
			SecretName: origCert.Name,
		},
	}

	log.Info("Creating ingress with original certificate")
	ingress, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate.Name, namespace.Name, &ingressTemplate.Spec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), ingress)

	log.Info("Creating new rotated certificate")
	secretData2 := map[string][]byte{
		corev1.TLSCertKey:       []byte(c.certData2),
		corev1.TLSPrivateKeyKey: []byte(c.keyData2),
	}
	rotatedCert, err := secrets.CreateCertificateSecret(c.client, c.cluster.ID, namespace.Name, secretData2, corev1.SecretTypeTLS)
	assert.NoError(c.T(), err)

	log.Info("Deleting old ingress")
	err = ingresses.DeleteIngress(c.client, c.cluster.ID, namespace.Name, ingress.Name)
	assert.NoError(c.T(), err)

	updatedIngressSpec := ingressTemplate.Spec.DeepCopy()
	updatedIngressSpec.TLS = []netv1.IngressTLS{
		{
			Hosts:      []string{"rotate.example.com"},
			SecretName: rotatedCert.Name,
		},
	}

	log.Info("Creating new ingress with rotated certificate")
	updatedIngress, err := ingresses.CreateIngress(c.client, c.cluster.ID, ingressTemplate.Name+"-rotated", namespace.Name, updatedIngressSpec)
	assert.NoError(c.T(), err)
	assert.NotNil(c.T(), updatedIngress)

	assert.Len(c.T(), updatedIngress.Spec.TLS, 1)
	assert.Equal(c.T(), rotatedCert.Name, updatedIngress.Spec.TLS[0].SecretName)

	log.Info("Successfully verified certificate rotation by replacing the ingress")
}

func TestCertificateTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateTestSuite))
}
