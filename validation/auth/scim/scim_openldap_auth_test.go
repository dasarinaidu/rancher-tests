//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.12 && !2.13

package scim

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	v3 "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/rancher/shepherd/extensions/defaults"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"

	cattlev3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	scimclient "github.com/rancher/shepherd/clients/rancher/auth/scim"
	oidcext "github.com/rancher/shepherd/extensions/auth/oidc"
	extfeatures "github.com/rancher/shepherd/extensions/kubeapi/features"
	extrbacapi "github.com/rancher/shepherd/extensions/kubeapi/rbac"
	"github.com/rancher/shepherd/extensions/users"
	"github.com/rancher/shepherd/pkg/clientbase"
	authactions "github.com/rancher/tests/actions/auth"
	rbacapi "github.com/rancher/tests/actions/kubeapi/rbac"
	scimactions "github.com/rancher/tests/actions/kubeapi/scim"
	rbac "github.com/rancher/tests/actions/rbac"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
)

type SCIMOpenLDAPAuthTestSuite struct {
	suite.Suite
	session    *session.Session
	client     *rancher.Client
	cluster    *v3.Cluster
	scimClient *scimclient.Client
}

func (s *SCIMOpenLDAPAuthTestSuite) SetupSuite() {
	s.session = session.NewSession()

	client, err := rancher.NewClient("", s.session)
	require.NoError(s.T(), err, "Failed to create Rancher client")
	s.client = client

	logrus.Info("Getting cluster name from the config file")
	clusterName := client.RancherConfig.ClusterName
	require.NotEmpty(s.T(), clusterName, "Cluster name should be set")

	clusterID, err := clusters.GetClusterIDByName(s.client, clusterName)
	require.NoError(s.T(), err, "Error getting cluster ID for cluster: %s", clusterName)

	s.cluster, err = s.client.Management.Cluster.ByID(clusterID)
	require.NoError(s.T(), err, "Failed to retrieve cluster by ID: %s", clusterID)

	logrus.Info("Setting up SCIM client for OpenLDAP provider")
	scimClient, err := scimactions.SetupSCIMClient(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err, "Failed to setup SCIM client")
	s.scimClient = scimClient

	require.NoError(s.T(), scimactions.VerifyExpectedBuildType(s.client), "The Rancher build type should match the one the config expects")

	servable, reason, err := scimactions.VerifySCIMServable(s.client)
	require.NoError(s.T(), err, "Failed to read whether this Rancher server serves SCIM")
	if !servable {
		s.T().Skip(reason)
	}

	logrus.Info("Ensuring baseline SCIM ConfigMap (enabled=true) for OpenLDAP provider")
	err = scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue})
	require.NoError(s.T(), err, "Failed to set baseline SCIM ConfigMap")
	err = scimactions.WaitForSCIMEndpointStatus(s.scimClient, http.StatusOK)
	require.NoError(s.T(), err, "SCIM endpoint should respond 200 after baseline ConfigMap set")
}

func (s *SCIMOpenLDAPAuthTestSuite) TearDownSuite() {
	if s.client != nil {
		ldapConfig, err := s.client.Management.AuthConfig.ByID(authactions.OpenLdap)
		if err == nil && ldapConfig.Enabled {
			logrus.Info("Disabling OpenLDAP authentication after test suite")
			err = s.client.Auth.OLDAP.Disable()
			if err != nil {
				logrus.WithError(err).Warn("Failed to disable OpenLDAP in teardown")
			}
		}
	}
	s.session.Cleanup()
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMFeatureFlagEnabled() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying SCIM feature flag is enabled")

	enabled, err := extfeatures.IsFeatureEnabled(s.client, scimactions.SCIMFeatureFlag)
	require.NoError(s.T(), err, "Failed to check SCIM feature flag state")
	require.True(s.T(), enabled, "SCIM feature flag should be enabled")

	resp, err := s.scimClient.Discovery().ServiceProviderConfig()
	require.NoError(s.T(), err, "GET /ServiceProviderConfig should not error")
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "ServiceProviderConfig should return 200"))
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMTokenSecretExistsInKubeAPI() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Infof("Verifying SCIM token secret exists via label selector for provider %s", authactions.OpenLdap)

	token, err := scimactions.FetchSCIMBearerToken(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err, "SCIM token secret should exist for provider %s", authactions.OpenLdap)
	require.NotEmpty(s.T(), token, "SCIM bearer token should not be empty")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMZFeatureFlagDisableAndReenableEndpoint() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Disabling SCIM flag and verifying /Users returns 404")

	err := extfeatures.UpdateFeatureFlag(s.client, scimactions.SCIMFeatureFlag, false)
	require.NoError(s.T(), err, "Should be able to disable SCIM feature flag")

	err = scimactions.WaitForSCIMEndpointStatus(s.scimClient, http.StatusNotFound)
	require.NoError(s.T(), err, "GET /Users should return 404 when SCIM is disabled")

	logrus.Info("Re-enabling SCIM flag after test")
	err = extfeatures.UpdateFeatureFlag(s.client, scimactions.SCIMFeatureFlag, true)
	require.NoError(s.T(), err, "Should be able to re-enable SCIM feature flag")

	logrus.Info("Waiting for Rancher to be fully operational after restart")
	require.NoError(s.T(), scimactions.WaitForRancherRestart(s.client, s.scimClient), "Rancher should be fully operational after feature flag re-enable")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMServiceProviderConfig() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /ServiceProviderConfig response")

	resp, err := s.scimClient.Discovery().ServiceProviderConfig()
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "ServiceProviderConfig should return 200"))

	var body map[string]interface{}
	err = resp.DecodeJSON(&body)
	require.NoError(s.T(), err, "Body should be valid JSON")
	require.Contains(s.T(), body, "schemas", "ServiceProviderConfig must have schemas field")
	require.Contains(s.T(), body, "patch", "ServiceProviderConfig must advertise patch support")
	require.Contains(s.T(), body, "filter", "ServiceProviderConfig must advertise filter support")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMResourceTypes() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /ResourceTypes lists Users and Groups")

	resp, err := s.scimClient.Discovery().ResourceTypes()
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "ResourceTypes should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)

	resourceTypes, ok := body["Resources"].([]interface{})
	require.True(s.T(), ok, "ResourceTypes response should have Resources array")
	require.GreaterOrEqual(s.T(), len(resourceTypes), 2, "Should have at least User and Group resource types")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMResourceTypeByID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /ResourceTypes/{id} for User and Group")

	for _, resourceTypeID := range []string{"User", "Group"} {
		resp, err := s.scimClient.Discovery().ResourceTypeByID(resourceTypeID)
		require.NoError(s.T(), err)
		require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, fmt.Sprintf("GET /ResourceTypes/%s should return 200", resourceTypeID)))

		var body map[string]interface{}
		require.NoError(s.T(), resp.DecodeJSON(&body))
		require.Equal(s.T(), resourceTypeID, body["id"], "ResourceType id should match requested id")
		require.Equal(s.T(), resourceTypeID, body["name"])
	}

	notFoundResp, err := s.scimClient.Discovery().ResourceTypeByID("nonexistent")
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(notFoundResp, http.StatusNotFound, "GET /ResourceTypes/nonexistent should return 404"))
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMSchemas() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Schemas returns User and Group schemas")

	resp, err := s.scimClient.Discovery().Schemas()
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Schemas should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	require.Contains(s.T(), body, "totalResults")

	resourceTypes, _ := body["Resources"].([]interface{})
	require.GreaterOrEqual(s.T(), len(resourceTypes), 2, "Schemas should include at least User and Group")

	ids := map[string]bool{}
	for _, resource := range resourceTypes {
		schema, ok := resource.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := schema["id"].(string)
		if !ok {
			continue
		}
		ids[id] = true
	}
	require.True(s.T(), ids[scimclient.SCIMSchemaUser], "Schemas should include User schema")
	require.True(s.T(), ids[scimclient.SCIMSchemaGroup], "Schemas should include Group schema")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMSchemaByID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Schemas/{id} for User and Group schemas")

	for _, schemaID := range []string{scimclient.SCIMSchemaUser, scimclient.SCIMSchemaGroup} {
		resp, err := s.scimClient.Discovery().SchemaByID(schemaID)
		require.NoError(s.T(), err)
		require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, fmt.Sprintf("GET /Schemas/%s should return 200", schemaID)))

		var body map[string]interface{}
		require.NoError(s.T(), resp.DecodeJSON(&body))
		require.Equal(s.T(), schemaID, body["id"], "Schema id should match requested id")
		require.Contains(s.T(), body, "attributes", "Schema should have attributes field")
	}

	notFoundResp, err := s.scimClient.Discovery().SchemaByID("urn:nonexistent")
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(notFoundResp, http.StatusNotFound, "GET /Schemas/nonexistent should return 404"))
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMInvalidTokenReturns401() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying invalid bearer token returns 401")

	badClient := scimclient.NewClient(&clientbase.ClientOpts{
		URL:      fmt.Sprintf("https://%s", s.client.RancherConfig.Host),
		TokenKey: "invalid-token",
		Insecure: true,
	}, authactions.OpenLdap)

	resp, err := badClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusUnauthorized, "Invalid token should return 401"))
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMRejectsRancherAdminToken() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying the Rancher admin token does not authenticate the SCIM endpoints")

	adminClient := scimactions.NewSCIMClientWithToken(s.client.RancherConfig.Host, authactions.OpenLdap, s.client.Management.APIBaseClient.Opts.TokenKey)

	resp, err := adminClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusUnauthorized, "A Rancher admin token should not reach the SCIM endpoints"))
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMRejectsStandardUserToken() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying a standard user token does not authenticate the SCIM endpoints")

	subClient, err := s.client.WithSession(subSession)
	require.NoError(s.T(), err)

	standardUser, err := users.CreateUserWithRole(subClient, users.UserConfig(), string(rbac.StandardUser))
	require.NoError(s.T(), err, "Should be able to create a standard user")

	standardUserClient, err := subClient.AsUser(standardUser)
	require.NoError(s.T(), err, "Standard user %s should be able to login", standardUser.Name)

	userSCIMClient := scimactions.NewSCIMClientWithToken(s.client.RancherConfig.Host, authactions.OpenLdap, standardUserClient.Management.APIBaseClient.Opts.TokenKey)

	resp, err := userSCIMClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusUnauthorized, "A standard user token should not reach the SCIM endpoints"))
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMRejectsAuthProviderUserToken() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying an OpenLDAP user token does not authenticate the SCIM endpoints")

	subClient, err := s.client.WithSession(subSession)
	require.NoError(s.T(), err)

	ldapAdmin := &v3.User{
		Username: s.client.Auth.OLDAP.Config.Users.Admin.Username,
		Password: s.client.Auth.OLDAP.Config.Users.Admin.Password,
	}

	authAdmin, err := authactions.LoginAsAuthUser(subClient, ldapAdmin, authactions.OpenLdap)
	require.NoError(s.T(), err, "OpenLDAP admin should be able to login")

	authSCIMClient := scimactions.NewSCIMClientWithToken(s.client.RancherConfig.Host, authactions.OpenLdap, authAdmin.Management.APIBaseClient.Opts.TokenKey)

	resp, err := authSCIMClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusUnauthorized, "An OpenLDAP user token should not reach the SCIM endpoints"))
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMTokenCannotReachRancherAPI() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying the SCIM bearer token grants no access to the Rancher API")

	token, err := scimactions.FetchSCIMBearerToken(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), token)

	resp, err := s.client.Auth.OIDC.RawRequest(http.MethodGet, oidcext.UsersPath, "Bearer "+token, nil)
	require.NoError(s.T(), err, "Should be able to reach the Rancher API with the SCIM token")
	require.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode, "The SCIM bearer token should not authenticate the Rancher API")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMOpenLDAPAuthUnaffectedBySCIM() {
	adminUser := &v3.User{
		Username: s.client.Auth.OLDAP.Config.Users.Admin.Username,
		Password: s.client.Auth.OLDAP.Config.Users.Admin.Password,
	}
	subSession, authAdmin, err := authactions.SetupAuthenticatedSession(s.client, s.session, adminUser, authactions.OpenLdap)
	require.NoError(s.T(), err, "OpenLDAP auth session should succeed while SCIM is enabled")
	defer subSession.Cleanup()

	logrus.Info("Verifying OpenLDAP login works while SCIM feature flag is enabled")

	_, err = authAdmin.Management.User.List(nil)
	require.NoError(s.T(), err, "Authenticated OpenLDAP admin should be able to list users")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMLocalAuthUnaffectedBySCIM() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying local admin auth unaffected by SCIM feature flag")

	_, err := s.client.Management.User.List(nil)
	require.NoError(s.T(), err, "Local admin should be able to list users while SCIM is enabled")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMTokenSecretStillPresentAfterAuthTests() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying SCIM token secret is still present via kubeapi after auth regression tests")

	token, err := scimactions.FetchSCIMBearerToken(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err, "SCIM secret should still be present after auth regression tests")
	require.NotEmpty(s.T(), token, "SCIM bearer token should still be non-empty")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMAuthConfigEnabledViaSteve() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying OpenLDAP authconfig reports enabled=true")

	authConfig, err := s.client.Management.AuthConfig.ByID(authactions.OpenLdap)
	require.NoError(s.T(), err, "Should be able to GET openldap authconfig")
	require.True(s.T(), authConfig.Enabled, "OpenLDAP authconfig should report enabled=true")
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMAuthUsersAsClusterMembers() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	authConfig := new(authactions.AuthConfig)
	config.LoadConfig(authactions.OpenLdapAuthInput, authConfig)
	require.NotEmpty(s.T(), authConfig.Users, "At least one auth user must be configured in cattle-config.yaml")

	for _, authUser := range authConfig.Users {
		logrus.Infof("Creating cluster-member CRTB for auth user %s", authUser.Username)

		userV3 := &v3.User{Username: authUser.Username, Password: authUser.Password}
		authAdmin, err := authactions.LoginAsAuthUser(s.client, userV3, authactions.OpenLdap)
		require.NoError(s.T(), err, "Auth user %s should be able to login", authUser.Username)

		mgmtUser, err := s.client.Management.User.ByID(authAdmin.UserID)
		require.NoError(s.T(), err, "Should fetch Rancher user for auth user %s", authUser.Username)

		crtbObj := &cattlev3.ClusterRoleTemplateBinding{
			ObjectMeta:       metav1.ObjectMeta{Namespace: s.cluster.ID, GenerateName: "crtb-"},
			ClusterName:      s.cluster.ID,
			UserName:         mgmtUser.ID,
			RoleTemplateName: string(rbac.ClusterMember),
		}
		_, err = extrbacapi.CreateClusterRoleTemplateBinding(s.client, crtbObj)
		require.NoError(s.T(), err, "Should be able to create CRTB for auth user %s", authUser.Username)

		crtbs, err := rbacapi.VerifyClusterRoleTemplateBindingForUser(s.client, mgmtUser.ID, 1)
		require.NoError(s.T(), err, "Should find exactly 1 CRTB for auth user %s", authUser.Username)
		require.Equal(s.T(), s.cluster.ID, crtbs[0].ClusterName, "CRTB should be for the correct cluster")
	}
}

func (s *SCIMOpenLDAPAuthTestSuite) TestSCIMZZDisableAuthCleansUpGroupsAndToken() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Creating SCIM groups to verify they are deleted on auth provider disable")

	_, groupID1, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)
	_, groupID2, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)
	groupIDs := []string{groupID1, groupID2}

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	_, err = scimactions.FetchSCIMBearerToken(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err, "Token secret should exist before disabling auth provider")

	logrus.Info("Disabling OpenLDAP auth provider to trigger SCIM cleanup")
	err = s.client.Auth.OLDAP.Disable()
	require.NoError(s.T(), err, "Should be able to disable OpenLDAP")

	logrus.Info("Waiting for SCIM groups to be deleted by cleanup controller")
	for _, gID := range groupIDs {
		err = scimactions.WaitForSCIMResourceDeletion(func() (int, error) {
			_, getErr := s.client.WranglerContext.Mgmt.Group().Get(gID, metav1.GetOptions{})
			if getErr != nil {
				return http.StatusNotFound, nil
			}
			return http.StatusOK, nil
		})
		require.NoError(s.T(), err, "SCIM group %s should be deleted after provider disable", gID)
	}

	logrus.Info("Verifying SCIM token secret is deleted")
	err = scimactions.WaitForSCIMResourceDeletion(func() (int, error) {
		_, fetchErr := scimactions.FetchSCIMBearerToken(s.client, authactions.OpenLdap)
		if fetchErr != nil {
			return http.StatusNotFound, nil
		}
		return http.StatusOK, nil
	})
	require.NoError(s.T(), err, "SCIM token secret should be deleted after provider disable")

	logrus.Infof("Verifying Rancher user %s is deleted when auth provider is disabled", userID)
	err = kwait.PollUntilContextTimeout(context.Background(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, false,
		func(ctx context.Context) (bool, error) {
			_, err := s.client.Management.User.ByID(userID)
			return err != nil, nil
		},
	)
	require.NoError(s.T(), err, "Rancher user %s should be deleted when auth provider is disabled", userID)
}

func TestSCIMOpenLDAPAuthSuite(t *testing.T) {
	suite.Run(t, new(SCIMOpenLDAPAuthTestSuite))
}
