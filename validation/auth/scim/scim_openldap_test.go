//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.12 && !2.13

package scim

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rancher/norman/types"
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

type SCIMOpenLDAPTestSuite struct {
	suite.Suite
	session    *session.Session
	client     *rancher.Client
	cluster    *v3.Cluster
	scimClient *scimclient.Client
}

func (s *SCIMOpenLDAPTestSuite) SetupSuite() {
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

func (s *SCIMOpenLDAPTestSuite) TearDownSuite() {
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

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNPatchUserActive() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH user with URN-prefixed active path behaves like bare path")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "urn:ietf:params:scim:schemas:core:2.0:User:active", false)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH URN-prefixed active should return 200"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), false, body["active"], "active should be false after URN-prefixed PATCH")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNPatchUserDisplayName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH user with URN-prefixed displayName path")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	newDisplayName := namegen.AppendRandomString("urn-display")
	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "urn:ietf:params:scim:schemas:core:2.0:User:displayName", newDisplayName)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH URN-prefixed displayName should return 200"))

	require.NoError(s.T(), scimactions.WaitForRancherUserName(s.client, userID, newDisplayName), "Rancher user.Name should reflect URN-prefixed displayName %q after PATCH", newDisplayName)
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNPatchUserName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH URN-prefixed userName succeeds when userIdAttribute=externalId")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, namegen.AppendRandomString("ext"), true)
	require.NoError(s.T(), err)

	newUserName := namegen.AppendRandomString("urn-rename") + "@example.com"
	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "urn:ietf:params:scim:schemas:core:2.0:User:userName", newUserName)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH URN-prefixed userName should return 200 with externalId principal"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNPatchGroupExternalID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH group with URN-prefixed externalId path")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	newExternalID := "ext-urn-" + groupName
	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "replace", "urn:ietf:params:scim:schemas:core:2.0:Group:externalId", newExternalID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH URN-prefixed group externalId should return 200"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), newExternalID, body["externalId"], "externalId should be updated")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNPatchGroupAddExternalID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH group op:add with URN-prefixed externalId is treated as replace")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	newExternalID := "ext-urn-add-" + groupName
	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "urn:ietf:params:scim:schemas:core:2.0:Group:externalId", newExternalID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH op:add URN-prefixed group externalId should return 200 (treated as replace)"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), newExternalID, body["externalId"], "externalId should be updated after PATCH op:add with URN prefix")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNPatchGroupAddMember() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH group op:add with URN-prefixed members path")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)
	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "urn:ietf:params:scim:schemas:core:2.0:Group:members", []scimclient.Member{{Value: userID}})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH op:add URN-prefixed members should return 200"))
	require.NoError(s.T(), scimactions.WaitForGroupMemberCount(s.scimClient, groupID, 1))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNPatchGroupRemoveMember() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH group op:remove with URN-prefixed members[value eq ...] path")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)
	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	addResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "members", []scimclient.Member{{Value: userID}})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(addResp, http.StatusOK, "PATCH add member should return 200"))

	removePath := fmt.Sprintf("urn:ietf:params:scim:schemas:core:2.0:Group:members[value eq %q]", userID)
	removeResp, err := scimactions.PatchGroup(s.scimClient, groupID, "remove", removePath, nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(removeResp, http.StatusOK, "PATCH op:remove URN-prefixed members should return 200"))
	require.NoError(s.T(), scimactions.WaitForGroupMemberCount(s.scimClient, groupID, 0))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNFilterUser() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Users?filter with URN-prefixed attribute path")

	userName, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("urn:ietf:params:scim:schemas:core:2.0:User:userName eq %q", userName))

	resp, err := s.scimClient.Users().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "URN-prefixed filter on /Users should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	userResources, _ := body["Resources"].([]interface{})
	require.Len(s.T(), userResources, 1, "URN-prefixed filter should return exactly 1 user")
	firstUser, _ := userResources[0].(map[string]interface{})
	require.Equal(s.T(), userName, firstUser["userName"], "Returned user userName should match filter")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNCrossResourceMismatchReturns400() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH group with User URN-prefixed path returns 400")

	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "replace", "urn:ietf:params:scim:schemas:core:2.0:User:displayName", "wrong")
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusBadRequest, "User URN on Group endpoint should return 400"))
	require.NoError(s.T(), scimactions.ValidateSCIMErrorBody(patchResp, http.StatusBadRequest))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNUnknownURNReturns400() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH user with unknown URN path returns 400 and does not panic")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "urn:custom:extension:1.0:Custom:foo", "bar")
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusBadRequest, "Unknown URN should return 400"))
	require.NoError(s.T(), scimactions.ValidateSCIMErrorBody(patchResp, http.StatusBadRequest))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMURNBareAttributesRegression() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying bare-path PATCH still works after URN-stripping addition (regression)")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	userPatchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "active", true)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(userPatchResp, http.StatusOK, "Bare-path PATCH active should still return 200"))

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	groupPatchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "replace", "externalId", "ext-"+groupName)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(groupPatchResp, http.StatusOK, "Bare-path PATCH group externalId should still return 200"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRLDisabledByDefault() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying rate limiting is disabled by default (no rate keys in ConfigMap)")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, scimactions.BaselineSCIMConfigMap(), http.StatusOK))

	results, err := scimactions.BurstSCIMRequests(s.scimClient, 50)
	require.NoError(s.T(), err)
	for i, code := range results {
		require.Equal(s.T(), http.StatusOK, code, "request %d should return 200 when rate limiting disabled", i)
	}
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRLEnabledReturns429AfterBurst() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying rate limit returns 429 when burst exceeded")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(2, 5)))

	results, err := scimactions.BurstSCIMRequests(s.scimClient, 20)
	require.NoError(s.T(), err)

	ok, throttled := scimactions.CountSCIMCodes(results)
	require.GreaterOrEqual(s.T(), ok, 1, "at least the burst capacity should return 200 (got ok=%d, 429=%d)", ok, throttled)
	require.GreaterOrEqual(s.T(), throttled, 1, "at least one request should be throttled with 429 (got ok=%d, 429=%d)", ok, throttled)
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRL429ResponseFormat() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying 429 response format (Retry-After header, scim+json content-type, SCIM error body)")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(1, 1)))

	throttledResp, err := scimactions.FindFirstThrottledResponse(s.scimClient, 10)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), throttledResp, "should observe at least one 429 within burst")

	require.Equal(s.T(), "application/scim+json", throttledResp.Header.Get("Content-Type"), "429 must use SCIM JSON content type")
	retryAfter, err := scimactions.GetRetryAfterSeconds(throttledResp)
	require.NoError(s.T(), err, "429 must include Retry-After header")
	require.Equal(s.T(), 1, retryAfter, "Retry-After should be 1 second")
	require.NoError(s.T(), scimactions.ValidateSCIMErrorBody(throttledResp, http.StatusTooManyRequests))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRLTokenBucketRefillAfterRetryAfter() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying token bucket refills after Retry-After period elapses")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(1, 1)))

	throttledResp, err := scimactions.FindFirstThrottledResponse(s.scimClient, 10)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), throttledResp, "should observe a 429 with Retry-After")
	_, err = scimactions.GetRetryAfterSeconds(throttledResp)
	require.NoError(s.T(), err)

	var resp *scimclient.Response
	err = kwait.PollUntilContextTimeout(context.Background(), defaults.FiveHundredMillisecondTimeout, defaults.OneMinuteTimeout, true, func(ctx context.Context) (bool, error) {
		r, listErr := s.scimClient.Users().List(nil)
		if listErr != nil {
			return false, nil
		}
		resp = r
		return r.StatusCode == http.StatusOK, nil
	})
	require.NoError(s.T(), err, "request after Retry-After window should eventually return 200")
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "request after Retry-After wait should return 200"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRLAppliesToAllMethods() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying rate limit applies to PATCH (non-GET method)")

	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, scimactions.BaselineSCIMConfigMap()))
	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(1, 1)))

	var ok, throttled int
	for i := 0; i < 10; i++ {
		resp, patchErr := scimactions.PatchUser(s.scimClient, userID, "replace", "active", i%2 == 0)
		require.NoError(s.T(), patchErr)
		switch resp.StatusCode {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			throttled++
		}
	}
	require.GreaterOrEqual(s.T(), throttled, 1, "rate limit should also apply to PATCH (got ok=%d, 429=%d)", ok, throttled)
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRLDynamicConfigChange() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying ConfigMap rate-limit change takes effect on next request without restart")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(1, 1)))

	throttled, err := scimactions.VerifySCIMThrottle(s.scimClient, 10)
	require.NoError(s.T(), err)
	require.True(s.T(), throttled, "rate limit should engage at low rps before reconfig")

	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(1000, 1000)))
	require.NoError(s.T(), scimactions.WaitForSCIMEndpointStatus(s.scimClient, http.StatusOK), "endpoint should serve 200 after raising rate limit (token bucket refill)")

	results, err := scimactions.BurstSCIMRequests(s.scimClient, 20)
	require.NoError(s.T(), err)
	ok, _ := scimactions.CountSCIMCodes(results)
	require.GreaterOrEqual(s.T(), ok, len(results)*8/10, "after raising rate limit to 1000 rps / burst 1000, the vast majority of a 20-request burst should return 200 (got ok=%d/%d)", ok, len(results))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRLInvalidValuesFallback() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying invalid rate-limit values fall back to defaults and do not crash")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{
		"enabled":                    "true",
		"rateLimitRequestsPerSecond": "not-a-number",
		"rateLimitBurst":             "-5",
	}, http.StatusOK))

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "SCIM should still serve requests with invalid rate-limit values"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRLReDisableRateLimit() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying rateLimitRequestsPerSecond=0 re-disables rate limiting")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(1, 1)))

	throttled, err := scimactions.VerifySCIMThrottle(s.scimClient, 10)
	require.NoError(s.T(), err)
	require.True(s.T(), throttled, "rate limit should engage with low rps")

	require.NoError(s.T(), scimactions.SetSCIMConfigMap(s.client, authactions.OpenLdap, scimactions.RateLimitSCIMConfigMap(0, 0)))

	results, err := scimactions.BurstSCIMRequests(s.scimClient, 50)
	require.NoError(s.T(), err)
	for i, code := range results {
		require.Equal(s.T(), http.StatusOK, code, "after re-disabling rate limit, request %d should return 200", i)
	}
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMGroupMemberMatchingUsesPrincipalName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying group PATCH add member resolves via principal Name (not DisplayName)")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)
	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "members", []scimclient.Member{{Value: userID}})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH add member by principal id should return 200"))
	require.NoError(s.T(), scimactions.WaitForGroupMemberCount(s.scimClient, groupID, 1))

	getResp, err := s.scimClient.Groups().ByID(groupID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(getResp, http.StatusOK, "GET /Groups/{id} should return 200"))

	body, err := scimactions.DecodeJSONBody(getResp)
	require.NoError(s.T(), err)
	members, _ := body["members"].([]interface{})
	require.Len(s.T(), members, 1, "Group should have exactly 1 member after PATCH add")
	member, _ := members[0].(map[string]interface{})
	require.Equal(s.T(), userID, member["value"], "Member value should resolve to the user principal id")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMZRegTokenRotation() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying SCIM token rotation: old token rejected, new token works")

	oldToken, err := scimactions.FetchSCIMBearerToken(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err, "Should fetch existing SCIM token")
	require.NotEmpty(s.T(), oldToken)

	secretNames, err := scimactions.FetchSCIMTokenSecretNames(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), secretNames, "Should find SCIM token secret")

	require.NoError(s.T(), scimactions.DeleteSCIMTokenSecrets(s.client, authactions.OpenLdap), "Should delete old SCIM token secrets")

	newToken, err := scimactions.CreateSCIMTokenSecret(s.client, authactions.OpenLdap)
	require.NoError(s.T(), err, "Should create a new SCIM token")
	require.NotEqual(s.T(), oldToken, newToken, "New token must differ from old")

	defer func() {
		s.scimClient = scimactions.NewSCIMClientWithToken(s.client.RancherConfig.Host, authactions.OpenLdap, newToken)
	}()

	oldClient := scimactions.NewSCIMClientWithToken(s.client.RancherConfig.Host, authactions.OpenLdap, oldToken)
	oldResp, err := oldClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(oldResp, http.StatusUnauthorized, "old SCIM token should be rejected with 401"))

	newClient := scimactions.NewSCIMClientWithToken(s.client.RancherConfig.Host, authactions.OpenLdap, newToken)
	newResp, err := newClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(newResp, http.StatusOK, "new SCIM token should be accepted with 200"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMRegConfigMapKeyParsingNonInterference() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying rate-limit ConfigMap keys do not interfere with parsing of enabled/paused/userIdAttribute")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWait(s.client, s.scimClient, authactions.OpenLdap, map[string]string{
		"enabled":                    "true",
		"paused":                     "false",
		"userIdAttribute":            "externalId",
		"rateLimitRequestsPerSecond": "1000",
		"rateLimitBurst":             "1000",
	}, http.StatusOK))

	externalID := namegen.AppendRandomString("ext-noninterference")
	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, externalID, true)
	require.NoError(s.T(), err)

	mgmtUser, err := s.client.Management.User.ByID(userID)
	require.NoError(s.T(), err)
	found := false
	for _, pid := range mgmtUser.PrincipalIDs {
		if strings.Contains(pid, externalID) {
			found = true
			break
		}
	}
	require.True(s.T(), found, "userIdAttribute=externalId should still apply when rate-limit keys are also set")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPostReprovisionsDisabledUser() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying POST with externalId matching a disabled user re-provisions and returns 200")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	externalID := namegen.AppendRandomString("ext-reprovision")
	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, externalID, true)
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "active", false)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH active=false should return 200"))

	resp, err := s.scimClient.Users().Create(scimclient.User{
		Schemas:    []string{scimclient.SCIMSchemaUser},
		UserName:   namegen.AppendRandomString("reprov-user"),
		ExternalID: externalID,
		Active:     scimclient.BoolPtr(true),
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "POST with externalId of disabled user should return 200 (re-provision)"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), userID, body["id"], "re-provisioned user should have the same id as the original (not a duplicate)")
	require.Equal(s.T(), true, body["active"], "re-provisioned user should be active")
	require.Equal(s.T(), externalID, body["externalId"], "externalId should match")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPostDuplicateActiveExternalIDReturns409() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying POST with externalId matching an active user returns 409")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	externalID := namegen.AppendRandomString("ext-dup-active")
	_, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, externalID, true)
	require.NoError(s.T(), err)

	resp, err := s.scimClient.Users().Create(scimclient.User{
		Schemas:    []string{scimclient.SCIMSchemaUser},
		UserName:   namegen.AppendRandomString("dup-user"),
		ExternalID: externalID,
		Active:     scimclient.BoolPtr(true),
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusConflict, "POST with externalId of active user should return 409"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPutUserNameImmutableReturns400() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PUT with changed userName returns 400 with scimType mutability")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	resp, err := s.scimClient.Users().Update(userID, scimclient.User{
		Schemas:  []string{scimclient.SCIMSchemaUser},
		UserName: namegen.AppendRandomString("renamed-put"),
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusBadRequest, "PUT with changed userName should return 400"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), "mutability", body["scimType"], "error body should have scimType=mutability")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPatchUserNameMutabilityError() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH op:replace userName returns 400 with scimType mutability when userName is principal")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	resp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "userName", namegen.AppendRandomString("renamed-patch"))
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusBadRequest, "PATCH op:replace userName should return 400"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), "mutability", body["scimType"], "error body should have scimType=mutability")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPatchRejectsEmptyUserName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH op:replace userName with an empty value returns 400, as PUT and POST already do")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	resp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "userName", "")
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusBadRequest, "PATCH op:replace userName with an empty value should return 400"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMCannotDeactivateDefaultAdmin() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH active=false on the default admin is refused and leaves the admin enabled")

	adminUsers, err := s.client.Management.User.List(&types.ListOpts{
		Filters: map[string]interface{}{"username": "admin"},
	})
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), adminUsers.Data, "default admin user should exist")

	adminID := adminUsers.Data[0].ID

	resp, err := scimactions.PatchUser(s.scimClient, adminID, "replace", "active", false)
	require.NoError(s.T(), err)
	require.Contains(s.T(), []int{http.StatusNotFound, http.StatusConflict}, resp.StatusCode,
		"PATCH active=false on the default admin should be refused as 404 when the provider owns no such user or 409 when it does, got: %s", string(resp.Body))

	admin, err := s.client.Management.User.ByID(adminID)
	require.NoError(s.T(), err, "Should be able to read the default admin after the refused PATCH")
	require.True(s.T(), *admin.Enabled, "The default admin should still be enabled")
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPatchExternalIDConflictReturns409() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH externalId to a value already held by another user returns 409 (userName mode, where externalId is mutable)")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, scimactions.BaselineSCIMConfigMap()))

	externalIDA := namegen.AppendRandomString("ext-conflict-a")
	_, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, externalIDA, true)
	require.NoError(s.T(), err)

	_, userIDB, err := scimactions.CreateSCIMUser(s.scimClient, subSession, namegen.AppendRandomString("ext-conflict-b"), true)
	require.NoError(s.T(), err)

	resp, err := scimactions.PatchUser(s.scimClient, userIDB, "replace", "externalId", externalIDA)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusConflict, "PATCH externalId to another user's value should return 409"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPutUserNameConflictReturns409() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PUT userName to a value already held by another user returns 409")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	userNameA, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, namegen.AppendRandomString("un-conflict-a-ext"), true)
	require.NoError(s.T(), err)

	externalIDB := namegen.AppendRandomString("un-conflict-b-ext")
	_, userIDB, err := scimactions.CreateSCIMUser(s.scimClient, subSession, externalIDB, true)
	require.NoError(s.T(), err)

	resp, err := s.scimClient.Users().Update(userIDB, scimclient.User{
		Schemas:    []string{scimclient.SCIMSchemaUser},
		UserName:   userNameA,
		ExternalID: externalIDB,
		Active:     scimclient.BoolPtr(true),
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusConflict, "PUT userName to another user's value should return 409"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPrincipalSearchUserNotLocal() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying a SCIM-provisioned user is not returned as a local principal by /v3/principals search")

	userName, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	require.NoError(s.T(), authactions.VerifyPrincipalNotLocal(s.client, userName))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPrincipalSearchGroupNotLocal() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying a SCIM-provisioned group is not returned as a local principal by /v3/principals search")

	groupName, _, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	require.NoError(s.T(), authactions.VerifyPrincipalNotLocal(s.client, groupName))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMGetUserMissingUserAttributeReturns200() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Users/{id} returns 200 for a SCIM user whose UserAttribute is absent (never logged in)")

	_, userID, err := scimactions.ProvisionSCIMUserWithoutAttribute(s.client, s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	resp, err := s.scimClient.Users().ByID(userID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Users/{id} should return 200 even when the user has no UserAttribute"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPutUserMissingUserAttributeReturns200() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PUT /Users/{id} returns 200 for a SCIM user whose UserAttribute is absent (externalId mode, userName mutable)")

	defer func() {
		require.NoError(s.T(), scimactions.RestoreSCIMBaseline(s.client, s.scimClient, authactions.OpenLdap))
	}()
	require.NoError(s.T(), scimactions.SetSCIMConfigMapAndWaitCreateReady(s.client, s.scimClient, authactions.OpenLdap, map[string]string{scimactions.SCIMConfigEnabledKey: scimactions.SCIMConfigTrue, scimactions.SCIMConfigUserIDAttributeKey: scimactions.SCIMConfigExternalIDValue}))

	externalID := namegen.AppendRandomString("ext-put-recover")
	_, userID, err := scimactions.ProvisionSCIMUserWithoutAttribute(s.client, s.scimClient, subSession, externalID)
	require.NoError(s.T(), err)

	resp, err := s.scimClient.Users().Update(userID, scimclient.User{
		Schemas:  []string{scimclient.SCIMSchemaUser},
		UserName: namegen.AppendRandomString("put-recovered"),
		Active:   scimclient.BoolPtr(true),
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "PUT /Users/{id} should return 200 even when the user has no UserAttribute"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPatchUserMissingUserAttributeReturns200() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH /Users/{id} returns 200 for a SCIM user whose UserAttribute is absent")

	_, userID, err := scimactions.ProvisionSCIMUserWithoutAttribute(s.client, s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	resp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "displayName", namegen.AppendRandomString("patched"))
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "PATCH /Users/{id} should return 200 even when the user has no UserAttribute"))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMGroupAddMemberMissingUserAttribute() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH group add member records membership when the member's UserAttribute is absent")

	_, userID, err := scimactions.ProvisionSCIMUserWithoutAttribute(s.client, s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "members", []scimclient.Member{{Value: userID}})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH group add member should return 200 when the member has no UserAttribute"))

	require.NoError(s.T(), scimactions.WaitForGroupMemberCount(s.scimClient, groupID, 1))
}

func (s *SCIMOpenLDAPTestSuite) TestSCIMPrincipalSearchLocalUserIsLocal() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying a genuine local user is still returned as a local principal by /v3/principals search")

	adminUsers, err := s.client.Management.User.List(&types.ListOpts{
		Filters: map[string]interface{}{"username": "admin"},
	})
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), adminUsers.Data, "default admin user should exist")

	require.NoError(s.T(), authactions.VerifyPrincipalIsLocal(s.client, adminUsers.Data[0].Username))
}

func TestSCIMOpenLDAPSuite(t *testing.T) {
	suite.Run(t, new(SCIMOpenLDAPTestSuite))
}
