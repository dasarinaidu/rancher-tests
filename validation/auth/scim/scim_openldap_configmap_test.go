//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.12 && !2.13

package scim

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	v3 "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/rancher/shepherd/extensions/defaults"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"

	scimclient "github.com/rancher/shepherd/clients/rancher/auth/scim"
	authactions "github.com/rancher/tests/actions/auth"
	scimactions "github.com/rancher/tests/actions/kubeapi/scim"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	kwait "k8s.io/apimachinery/pkg/util/wait"
)

type SCIMOpenLDAPConfigMapTestSuite struct {
	suite.Suite
	session    *session.Session
	client     *rancher.Client
	cluster    *v3.Cluster
	scimClient *scimclient.Client
}

func (s *SCIMOpenLDAPConfigMapTestSuite) SetupSuite() {
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

func (s *SCIMOpenLDAPConfigMapTestSuite) TearDownSuite() {
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

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMInvalidTokenReturns401WithoutConfigMap() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying an invalid bearer token returns 401 when the ConfigMap is absent, so the answer does not report the provider state")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.DeleteSCIMConfigMap(s.client, authactions.OpenLdap))
	require.NoError(s.T(), scimactions.WaitForSCIMEndpointStatus(s.scimClient, http.StatusNotFound))

	badClient := scimactions.NewSCIMClientWithToken(s.client.RancherConfig.Host, authactions.OpenLdap, "invalid-token")
	resp, err := badClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusUnauthorized, "An invalid token should return 401 whether or not the ConfigMap is present"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMEnabledTrueReturns200() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying enabled=true returns 200 on /Users after being disabled")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigFalse}, http.StatusNotFound))
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, scimactions.BaselineSCIMConfigMap(), http.StatusOK))

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Users should return 200 with enabled=true"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMEnabledFalseReturns404() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying enabled=false returns 404 on /Users")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigFalse}, http.StatusNotFound))

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusNotFound, "GET /Users should return 404 with enabled=false"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMMissingEnabledKeyReturns404() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying a ConfigMap without the enabled key falls back to disabled and returns 404 on /Users")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigUserNameValue}, http.StatusNotFound))

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusNotFound, "GET /Users should return 404 when the ConfigMap omits the enabled key"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMInvalidEnabledValueReturns404() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying an unparseable enabled value falls back to disabled and returns 404 on /Users")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: "notabool"}, http.StatusNotFound))

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusNotFound, "GET /Users should return 404 when the enabled value does not parse as a bool"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMPausedReturns503() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying paused=true returns 503 on /Users")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigPausedKey: scimactions.SCIMConfigTrue}, http.StatusServiceUnavailable))

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusServiceUnavailable, "GET /Users should return 503 when paused"))
	require.NoError(s.T(), scimactions.ValidateSCIMErrorBody(resp, http.StatusServiceUnavailable))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMUnpauseResumes() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying unpause (paused=false) resumes SCIM endpoints")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigPausedKey: scimactions.SCIMConfigTrue}, http.StatusServiceUnavailable))
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigPausedKey: scimactions.SCIMConfigFalse}, http.StatusOK))

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Users should return 200 after unpause"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMUserIdExternalIDPrincipal() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying userIdAttribute=externalId builds Rancher user principalID from externalId")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	externalID := namegen.AppendRandomString("ext")
	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, externalID, true)
	require.NoError(s.T(), err)

	mgmtUser, err := s.client.Management.User.ByID(userID)
	require.NoError(s.T(), err, "Should fetch Rancher user for SCIM user %s", userID)
	require.NotEmpty(s.T(), mgmtUser.PrincipalIDs, "Rancher user should have principalIDs")

	found := false
	for _, pid := range mgmtUser.PrincipalIDs {
		if strings.Contains(pid, externalID) {
			found = true
			break
		}
	}
	require.True(s.T(), found, "At least one principalID should contain externalId %q (got %v)", externalID, mgmtUser.PrincipalIDs)
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMUserNameChangeAcceptedWithExternalIDPrincipal() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH userName succeeds when userIdAttribute=externalId")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, namegen.AppendRandomString("ext"), true)
	require.NoError(s.T(), err)

	newUserName := namegen.AppendRandomString("renamed") + "@example.com"
	resp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "userName", newUserName)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "PATCH userName should return 200 when externalId is principal"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMUserNameChangeRejectedWithUserNamePrincipal() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH userName returns 400 when userName is the principal (default)")

	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, scimactions.BaselineSCIMConfigMap()))

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	resp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "userName", "newname@example.com")
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusBadRequest, "PATCH userName should return 400 when userName is principal"))
	require.NoError(s.T(), scimactions.ValidateSCIMErrorBody(resp, http.StatusBadRequest))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMGroupIdExternalIDPrincipal() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying groupIdAttribute=externalId is accepted and group created with externalId")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigGroupIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	externalID := namegen.AppendRandomString("grp-ext")
	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, externalID)
	require.NoError(s.T(), err)

	getResp, err := s.scimClient.Groups().ByID(groupID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(getResp, http.StatusOK, "GET /Groups/{id} should return 200"))

	body, err := scimactions.DecodeJSONBody(getResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), externalID, body["externalId"], "externalId should be set on the group")
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMDisplayNameFallsBackToUserName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying Rancher user.Name (displayName) falls back to userName when SCIM displayName is not set")

	userName, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	mgmtUser, err := s.client.Management.User.ByID(userID)
	require.NoError(s.T(), err, "Should fetch Rancher user for SCIM user %s", userID)
	require.Equal(s.T(), userName, mgmtUser.Name, "Rancher user.Name should fall back to userName when SCIM displayName is not provided")
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMPatchUserDisplayName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH replace displayName on user succeeds and is reflected in Rancher user record")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	newDisplayName := namegen.AppendRandomString("display")
	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "displayName", newDisplayName)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH displayName should return 200"))

	err = kwait.PollUntilContextTimeout(context.Background(), defaults.FiveSecondTimeout, defaults.OneMinuteTimeout, false, func(ctx context.Context) (bool, error) {
		mgmtUser, getErr := s.client.Management.User.ByID(userID)
		if getErr != nil {
			return false, nil
		}
		return mgmtUser.Name == newDisplayName, nil
	})
	require.NoError(s.T(), err, "Rancher user.Name should reflect SCIM displayName %q after PATCH", newDisplayName)
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMFilterUserByExternalID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Users?filter=externalId eq returns matching user")

	externalID := namegen.AppendRandomString("ext-filter")
	_, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, externalID, true)
	require.NoError(s.T(), err)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("externalId eq %q", externalID))

	resp, err := s.scimClient.Users().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "Filtered GET /Users should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	userResources, _ := body["Resources"].([]interface{})
	require.Len(s.T(), userResources, 1, "Filter by externalId should return exactly 1 user")

	firstUser, _ := userResources[0].(map[string]interface{})
	require.Equal(s.T(), externalID, firstUser["externalId"], "Returned user externalId should match filter")
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMFilterGroupByExternalID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Groups?filter=externalId eq returns matching group")

	externalID := namegen.AppendRandomString("grp-ext-filter")
	_, _, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, externalID)
	require.NoError(s.T(), err)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("externalId eq %q", externalID))

	resp, err := s.scimClient.Groups().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "Filtered GET /Groups should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	groupResources, _ := body["Resources"].([]interface{})
	require.Len(s.T(), groupResources, 1, "Filter by externalId should return exactly 1 group")

	firstGroup, _ := groupResources[0].(map[string]interface{})
	require.Equal(s.T(), externalID, firstGroup["externalId"], "Returned group externalId should match filter")
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMCMInvalidUserIdAttributeFallsBack() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying invalid userIdAttribute value falls back to default and does not crash SCIM")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: "badvalue"}))

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), userID, "POST /Users should still succeed with invalid userIdAttribute (fallback to default)")

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Users should still return 200 with invalid userIdAttribute"))
}

func (s *SCIMOpenLDAPConfigMapTestSuite) TestSCIMNoConfigMapAllEndpointsReturn404() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying all SCIM endpoints return 404 with SCIM error body when ConfigMap is absent")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.DeleteSCIMConfigMap(s.client, authactions.OpenLdap))
	require.NoError(s.T(), scimactions.WaitForSCIMEndpointStatus(s.scimClient, http.StatusNotFound))

	endpoints := []struct {
		name string
		call func() (*scimclient.Response, error)
	}{
		{"GET /Users", func() (*scimclient.Response, error) { return s.scimClient.Users().List(nil) }},
		{"GET /Groups", func() (*scimclient.Response, error) { return s.scimClient.Groups().List(nil) }},
		{"GET /ServiceProviderConfig", func() (*scimclient.Response, error) { return s.scimClient.Discovery().ServiceProviderConfig() }},
		{"GET /ResourceTypes", func() (*scimclient.Response, error) { return s.scimClient.Discovery().ResourceTypes() }},
		{"GET /Schemas", func() (*scimclient.Response, error) { return s.scimClient.Discovery().Schemas() }},
	}
	for _, ep := range endpoints {
		resp, err := ep.call()
		require.NoError(s.T(), err, "%s should not error", ep.name)
		require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusNotFound, fmt.Sprintf("%s should return 404 when ConfigMap absent", ep.name)))
		require.NoError(s.T(), scimactions.ValidateSCIMErrorBody(resp, http.StatusNotFound), "%s 404 body should match SCIM error schema", ep.name)
	}
}

func TestSCIMOpenLDAPConfigMapSuite(t *testing.T) {
	suite.Run(t, new(SCIMOpenLDAPConfigMapTestSuite))
}
