//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress

package certificate

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/rancher/shepherd/pkg/session"
	clusterapi "github.com/rancher/tests/actions/kubeapi/clusters"
	"github.com/rancher/tests/actions/projects"
	"github.com/rancher/tests/actions/rbac"
	"github.com/rancher/tests/actions/secrets"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CertificateRBACTestSuite struct {
	suite.Suite
	client   *rancher.Client
	session  *session.Session
	cluster  *management.Cluster
	certData string
	keyData  string
}

func (cert *CertificateRBACTestSuite) SetupSuite() {
	cert.session = session.NewSession()

	client, err := rancher.NewClient("", cert.session)
	assert.NoError(cert.T(), err)
	cert.client = client

	log.Info("Getting cluster name from the config file")
	clusterName := client.RancherConfig.ClusterName
	require.NotEmptyf(cert.T(), clusterName, "Cluster name should be set")

	clusterID, err := clusters.GetClusterIDByName(cert.client, clusterName)
	require.NoError(cert.T(), err, "Error getting cluster ID")

	cert.cluster, err = cert.client.Management.Cluster.ByID(clusterID)
	assert.NoError(cert.T(), err)

	log.Info("Generating self signed test certificate and key for certificate operations")
	cert.certData, cert.keyData, err = secrets.GenerateSelfSignedCert()
	assert.NoError(cert.T(), err)
	log.Info("Certificate and key generated successfully")
}

func (cert *CertificateRBACTestSuite) TearDownSuite() {
	cert.session.Cleanup()
}

func (cert *CertificateRBACTestSuite) TestCreateCertificateSecret() {
	subSession := cert.session.NewSession()
	defer subSession.Cleanup()

	tests := []struct {
		role   rbac.Role
		member string
	}{
		{rbac.ClusterOwner, rbac.StandardUser.String()},
		{rbac.ClusterMember, rbac.StandardUser.String()},
		{rbac.ProjectOwner, rbac.StandardUser.String()},
		{rbac.ProjectMember, rbac.StandardUser.String()},
		{rbac.ReadOnly, rbac.StandardUser.String()},
	}

	for _, tt := range tests {
		cert.Run("Validate certificate creation for user with role "+tt.role.String(), func() {
			log.Info("Create a project and a namespace in the project.")
			adminProject, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(cert.client, cert.cluster.ID)
			assert.NoError(cert.T(), err)

			log.Infof("Create a standard user and add the user to a cluster/project role %s", tt.role)
			_, standardUserClient, err := rbac.AddUserWithRoleToCluster(cert.client, tt.member, tt.role.String(), cert.cluster, adminProject)
			assert.NoError(cert.T(), err)

			log.Infof("As a %v, create a TLS secret in the namespace %v", tt.role.String(), namespace.Name)
			secretData := map[string][]byte{
				corev1.TLSCertKey:       []byte(cert.certData),
				corev1.TLSPrivateKeyKey: []byte(cert.keyData),
			}

			createdCert, err := secrets.CreateCertificateSecret(standardUserClient, cert.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)

			switch tt.role.String() {
			case rbac.ClusterOwner.String(), rbac.ProjectOwner.String(), rbac.ProjectMember.String():
				assert.NoError(cert.T(), err, "failed to create a TLS secret")
				assert.NotNil(cert.T(), createdCert)

				standardUserContext, err := clusterapi.GetClusterWranglerContext(standardUserClient, cert.cluster.ID)
				assert.NoError(cert.T(), err)

				retrievedSecret, err := standardUserContext.Core.Secret().Get(namespace.Name, createdCert.Name, metav1.GetOptions{})
				assert.NoError(cert.T(), err)
				assert.Equal(cert.T(), corev1.SecretTypeTLS, retrievedSecret.Type)
				log.Infof("TLS Secret %s created successfully by user with role %s", createdCert.Name, tt.role.String())

			case rbac.ClusterMember.String(), rbac.ReadOnly.String():
				assert.Error(cert.T(), err)
				assert.True(cert.T(), errors.IsForbidden(err))
			}
		})
	}
}

func (cert *CertificateRBACTestSuite) TestListCertificateSecret() {
	subSession := cert.session.NewSession()
	defer subSession.Cleanup()
	tests := []struct {
		role   rbac.Role
		member string
	}{
		{rbac.ClusterOwner, rbac.StandardUser.String()},
		{rbac.ClusterMember, rbac.StandardUser.String()},
		{rbac.ProjectOwner, rbac.StandardUser.String()},
		{rbac.ProjectMember, rbac.StandardUser.String()},
		{rbac.ReadOnly, rbac.StandardUser.String()},
	}

	for _, tt := range tests {

		cert.Run("Validate listing TLS secret for user with role "+tt.role.String(), func() {
			log.Info("Create a project and a namespace in the project.")
			adminProject, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(cert.client, cert.cluster.ID)
			assert.NoError(cert.T(), err)

			log.Infof("Create a standard user and add the user to a cluster/project role %s", tt.role)
			newUser, standardUserClient, err := rbac.AddUserWithRoleToCluster(cert.client, tt.member, tt.role.String(), cert.cluster, adminProject)
			assert.NoError(cert.T(), err)
			cert.T().Logf("Created user: %v", newUser.Username)

			log.Infof("As admin, create a TLS secret in the namespace %v", namespace.Name)
			secretData := map[string][]byte{
				corev1.TLSCertKey:       []byte(cert.certData),
				corev1.TLSPrivateKeyKey: []byte(cert.keyData),
			}

			createdCert, err := secrets.CreateCertificateSecret(cert.client, cert.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
			assert.NoError(cert.T(), err, "failed to create a TLS secret")
			assert.NotNil(cert.T(), createdCert)

			log.Infof("As a %v, list the TLS secrets.", tt.role.String())
			standardUserContext, err := clusterapi.GetClusterWranglerContext(standardUserClient, cert.cluster.ID)
			assert.NoError(cert.T(), err)

			secretList, err := standardUserContext.Core.Secret().List(namespace.Name, metav1.ListOptions{})

			switch tt.role.String() {
			case rbac.ClusterOwner.String(), rbac.ProjectOwner.String(), rbac.ProjectMember.String():
				assert.NoError(cert.T(), err, "failed to list TLS secrets")
				assert.NotEmpty(cert.T(), secretList.Items)

				found := false
				for _, secret := range secretList.Items {
					if secret.Name == createdCert.Name {
						found = true
						break
					}
				}
				assert.True(cert.T(), found, "Created TLS secret not found in the list")
				log.Infof("TLS Secret %s listed successfully by user with role %s", createdCert.Name, tt.role.String())

			case rbac.ClusterMember.String(), rbac.ReadOnly.String():
				if err == nil {
					log.Infof("TLS Secret listing was allowed for cluster member")
				} else {
					log.Infof("TLS Secret listing failed for cluster member: %v", err)
					assert.True(cert.T(), errors.IsForbidden(err))
				}
			}
		})
	}
}

func (cert *CertificateRBACTestSuite) TestUpdateCertificateSecret() {
	subSession := cert.session.NewSession()
	defer subSession.Cleanup()

	tests := []struct {
		role   rbac.Role
		member string
	}{
		{rbac.ClusterOwner, rbac.StandardUser.String()},
		{rbac.ClusterMember, rbac.StandardUser.String()},
		{rbac.ProjectOwner, rbac.StandardUser.String()},
		{rbac.ProjectMember, rbac.StandardUser.String()},
		{rbac.ReadOnly, rbac.StandardUser.String()},
	}

	for _, tt := range tests {

		cert.Run("Validate updating TLS secret as user with role "+tt.role.String(), func() {
			log.Info("Create a project and a namespace in the project.")
			adminProject, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(cert.client, cert.cluster.ID)
			assert.NoError(cert.T(), err)

			log.Infof("Create a standard user and add the user to a cluster/project role %s", tt.role)
			newUser, standardUserClient, err := rbac.AddUserWithRoleToCluster(cert.client, tt.member, tt.role.String(), cert.cluster, adminProject)
			assert.NoError(cert.T(), err)
			cert.T().Logf("Created user: %v", newUser.Username)

			log.Infof("As admin, create a TLS secret in the namespace %v", namespace.Name)
			secretData := map[string][]byte{
				corev1.TLSCertKey:       []byte(cert.certData),
				corev1.TLSPrivateKeyKey: []byte(cert.keyData),
			}

			createdCert, err := secrets.CreateCertificateSecret(cert.client, cert.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
			assert.NoError(cert.T(), err, "failed to create a TLS secret")
			assert.NotNil(cert.T(), createdCert)

			log.Infof("As a %v, update the TLS secret.", tt.role.String())
			standardUserContext, err := clusterapi.GetClusterWranglerContext(standardUserClient, cert.cluster.ID)
			assert.NoError(cert.T(), err)

			retrievedSecret, err := standardUserContext.Core.Secret().Get(namespace.Name, createdCert.Name, metav1.GetOptions{})
			if err == nil {
				if retrievedSecret.Labels == nil {
					retrievedSecret.Labels = make(map[string]string)
				}
				retrievedSecret.Labels["updated-by"] = tt.role.String()

				_, err = standardUserContext.Core.Secret().Update(retrievedSecret)

				switch tt.role.String() {
				case rbac.ClusterOwner.String(), rbac.ProjectOwner.String(), rbac.ProjectMember.String():
					assert.NoError(cert.T(), err, "failed to update TLS secret")
					log.Infof("TLS Secret %s updated successfully by user with role %s", createdCert.Name, tt.role.String())

				case rbac.ClusterMember.String(), rbac.ReadOnly.String():
					assert.Error(cert.T(), err)
					assert.True(cert.T(), errors.IsForbidden(err))
				}
			} else {
				if tt.role.String() == rbac.ClusterMember.String() || tt.role.String() == rbac.ReadOnly.String() {
					assert.Error(cert.T(), err)
					log.Infof("TLS Secret retrieval failed for user with role %s as expected", tt.role.String())
				} else {
					assert.NoError(cert.T(), err, "failed to retrieve TLS secret")
				}
			}
		})
	}
}

func (cert *CertificateRBACTestSuite) TestDeleteCertificateSecret() {
	subSession := cert.session.NewSession()
	defer subSession.Cleanup()

	tests := []struct {
		role   rbac.Role
		member string
	}{
		{rbac.ClusterOwner, rbac.StandardUser.String()},
		{rbac.ClusterMember, rbac.StandardUser.String()},
		{rbac.ProjectOwner, rbac.StandardUser.String()},
		{rbac.ProjectMember, rbac.StandardUser.String()},
		{rbac.ReadOnly, rbac.StandardUser.String()},
	}

	for _, tt := range tests {

		cert.Run("Validate deleting TLS secret as user with role "+tt.role.String(), func() {
			log.Info("Create a project and a namespace in the project.")
			adminProject, namespace, err := projects.CreateProjectAndNamespaceUsingWrangler(cert.client, cert.cluster.ID)
			assert.NoError(cert.T(), err)

			log.Infof("Create a standard user and add the user to a cluster/project role %s", tt.role)
			newUser, standardUserClient, err := rbac.AddUserWithRoleToCluster(cert.client, tt.member, tt.role.String(), cert.cluster, adminProject)
			assert.NoError(cert.T(), err)
			cert.T().Logf("Created user: %v", newUser.Username)

			log.Infof("As admin, create a TLS secret in the namespace %v", namespace.Name)
			secretData := map[string][]byte{
				corev1.TLSCertKey:       []byte(cert.certData),
				corev1.TLSPrivateKeyKey: []byte(cert.keyData),
			}

			createdCert, err := secrets.CreateCertificateSecret(cert.client, cert.cluster.ID, namespace.Name, secretData, corev1.SecretTypeTLS)
			assert.NoError(cert.T(), err, "failed to create a TLS secret")
			assert.NotNil(cert.T(), createdCert)

			log.Infof("As a %v, delete the TLS secret.", tt.role.String())
			standardUserContext, err := clusterapi.GetClusterWranglerContext(standardUserClient, cert.cluster.ID)
			assert.NoError(cert.T(), err)

			err = standardUserContext.Core.Secret().Delete(namespace.Name, createdCert.Name, &metav1.DeleteOptions{})

			switch tt.role.String() {
			case rbac.ClusterOwner.String(), rbac.ProjectOwner.String(), rbac.ProjectMember.String():
				assert.NoError(cert.T(), err, "failed to delete TLS secret")

				_, err = standardUserContext.Core.Secret().Get(namespace.Name, createdCert.Name, metav1.GetOptions{})
				assert.Error(cert.T(), err, "TLS Secret should be deleted")
				log.Infof("TLS Secret %s deleted successfully by user with role %s", createdCert.Name, tt.role.String())

			case rbac.ClusterMember.String(), rbac.ReadOnly.String():
				assert.Error(cert.T(), err)
				assert.True(cert.T(), errors.IsForbidden(err))
			}
		})
	}
}

func TestCertificateRBACTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateRBACTestSuite))
}
