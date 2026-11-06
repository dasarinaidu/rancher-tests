//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress && !2.8 && !2.9 && !2.10 && !2.11 && !2.12 && !2.13

package scim

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	v3 "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/clusters"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"

	cattlev3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	scimclient "github.com/rancher/shepherd/clients/rancher/auth/scim"
	extrbacapi "github.com/rancher/shepherd/extensions/kubeapi/rbac"
	authactions "github.com/rancher/tests/actions/auth"
	projectapi "github.com/rancher/tests/actions/kubeapi/projects"
	rbacapi "github.com/rancher/tests/actions/kubeapi/rbac"
	scimactions "github.com/rancher/tests/actions/kubeapi/scim"
	rbac "github.com/rancher/tests/actions/rbac"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SCIMOpenLDAPCRUDTestSuite struct {
	suite.Suite
	session    *session.Session
	client     *rancher.Client
	cluster    *v3.Cluster
	scimClient *scimclient.Client
}

func (s *SCIMOpenLDAPCRUDTestSuite) SetupSuite() {
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

func (s *SCIMOpenLDAPCRUDTestSuite) TearDownSuite() {
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

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMListUsers() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Users returns 200 with valid ListResponse")

	resp, err := s.scimClient.Users().List(nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Users should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	require.Contains(s.T(), body, "totalResults", "ListResponse should have totalResults")
	require.Contains(s.T(), body, "Resources", "ListResponse should have Resources array")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMCreateAndGetUser() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Creating SCIM user with externalID")

	userName, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "ext-"+namegen.AppendRandomString("id"), true)
	require.NoError(s.T(), err)

	getResp, err := s.scimClient.Users().ByID(userID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(getResp, http.StatusOK, "GET /Users/{id} should return 200"))

	body, err := scimactions.DecodeJSONBody(getResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), userName, body["userName"], "userName in response should match created value")
	require.Equal(s.T(), userID, body["id"], "id in response should match")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMCreateDuplicateUserReturns409() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying duplicate userName returns 409")

	userName, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	resp2, err := s.scimClient.Users().Create(scimclient.User{
		Schemas:  []string{scimclient.SCIMSchemaUser},
		UserName: userName,
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp2, http.StatusConflict, "Duplicate POST /Users should return 409"))
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMFilterUserByUserName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying filter by userName")

	userName, _, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("userName eq %q", userName))

	filterResp, err := s.scimClient.Users().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(filterResp, http.StatusOK, "Filtered GET /Users should return 200"))

	body, err := scimactions.DecodeJSONBody(filterResp)
	require.NoError(s.T(), err)

	userResources, _ := body["Resources"].([]interface{})
	require.Len(s.T(), userResources, 1, "Filter should return exactly 1 user")

	firstUser, _ := userResources[0].(map[string]interface{})
	require.Equal(s.T(), userName, firstUser["userName"], "Returned user userName should match filter")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchDeactivateUser() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH deactivate for user")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	getResp, err := s.scimClient.Users().ByID(userID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(getResp, http.StatusOK, "GET /Users/{id} should return 200 before PATCH"))

	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "active", false)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH active=false should return 200"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), false, body["active"], "active should be false after deactivation")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchReactivateUser() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH reactivate for user")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	deactivateResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "active", false)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(deactivateResp, http.StatusOK, "PATCH active=false should return 200"))

	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "active", true)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH active=true should return 200"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), true, body["active"], "active should be true after reactivation")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMDeleteUser() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying DELETE /Users/{id}")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	deleteResp, err := s.scimClient.Users().Delete(userID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(deleteResp, http.StatusNoContent, "DELETE /Users/{id} should return 204"))

	err = scimactions.WaitForSCIMResourceDeletion(func() (int, error) {
		resp, pollErr := s.scimClient.Users().ByID(userID)
		if pollErr != nil {
			return 0, nil
		}
		return resp.StatusCode, nil
	})
	require.NoError(s.T(), err, "User %s should return 404 after DELETE", userID)
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMGetNonExistentUserReturns404() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Users/nonexistent-id returns 404")

	resp, err := s.scimClient.Users().ByID("nonexistent-id-99999")
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusNotFound, "GET non-existent user should return 404"))
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMUserPagination() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying /Users startIndex and count pagination parameters")

	params := url.Values{}
	params.Set("startIndex", "1")
	params.Set("count", "2")

	resp, err := s.scimClient.Users().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "Paginated GET /Users should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	require.Contains(s.T(), body, "totalResults", "Paginated response should include totalResults")
	require.Contains(s.T(), body, "startIndex", "Paginated response should echo startIndex")
	require.Contains(s.T(), body, "itemsPerPage", "Paginated response should include itemsPerPage")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMOutOfBoundsStartIndexReturnsEmpty() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying /Users?startIndex=9999 returns empty Resources, not 404")

	params := url.Values{}
	params.Set("startIndex", "9999")
	params.Set("count", "5")

	resp, err := s.scimClient.Users().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "Out-of-bounds startIndex should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)

	userResources, _ := body["Resources"].([]interface{})
	require.Empty(s.T(), userResources, "Resources should be empty for out-of-bounds startIndex")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMCreateAndGetGroup() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Creating SCIM group")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	getResp, err := s.scimClient.Groups().ByID(groupID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(getResp, http.StatusOK, "GET /Groups/{id} should return 200"))

	body, err := scimactions.DecodeJSONBody(getResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), groupName, body["displayName"], "displayName should match")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMCreateDuplicateGroupReturns409() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying duplicate group displayName returns 409")

	groupName, _, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	resp2, err := s.scimClient.Groups().Create(scimclient.Group{
		Schemas:     []string{scimclient.SCIMSchemaGroup},
		DisplayName: groupName,
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp2, http.StatusConflict, "Duplicate POST /Groups should return 409"))
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchAddMemberToGroup() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH add member to group")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "members", []scimclient.Member{{Value: userID}})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH add member should return 200"))

	err = scimactions.WaitForGroupMemberCount(s.scimClient, groupID, 1)
	require.NoError(s.T(), err, "Timed out waiting for group member to appear via GET")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchRemoveMemberFromGroup() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH remove member from group")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", true)
	require.NoError(s.T(), err)

	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	addResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "members", []scimclient.Member{{Value: userID}})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(addResp, http.StatusOK, "PATCH add member should return 200"))

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "remove", fmt.Sprintf("members[value eq %q]", userID), nil)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH remove member should return 200"))

	err = scimactions.WaitForGroupMemberCount(s.scimClient, groupID, 0)
	require.NoError(s.T(), err, "Timed out waiting for group member to be removed via GET")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMGroupListExcludeMembersAttribute() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Groups?excludedAttributes=members omits members field")

	params := url.Values{}
	params.Set("excludedAttributes", "members")

	resp, err := s.scimClient.Groups().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Groups?excludedAttributes=members should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)

	groupResources, _ := body["Resources"].([]interface{})
	for _, rawGroup := range groupResources {
		group, _ := rawGroup.(map[string]interface{})
		_, hasMembersField := group["members"]
		require.False(s.T(), hasMembersField, "members field should be absent when excludedAttributes=members")
	}
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMCannotViewDefaultAdmin() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying default admin user is not visible via SCIM (local users are not SCIM-provisioned)")

	params := url.Values{}
	params.Set("filter", `username eq "admin"`)

	resp, err := s.scimClient.Users().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "Filter request should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)

	userResources, _ := body["Resources"].([]interface{})
	require.Empty(s.T(), userResources, "Local admin should not appear in SCIM — only SCIM-provisioned users are returned")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchNonExistentUserReturns404() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH active=false on non-existent SCIM user returns 404")

	patchResp, err := scimactions.PatchUser(s.scimClient, "nonexistent-admin-id", "replace", "active", false)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusNotFound, "PATCH on non-existent user should return 404"))
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMGroupRoleBindings() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying group CRTB for SCIM group")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	var userIDs []string
	for i := 0; i < 2; i++ {
		_, uid, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
		require.NoError(s.T(), err)
		userIDs = append(userIDs, uid)

		addResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "members", []scimclient.Member{{Value: uid}})
		require.NoError(s.T(), err)
		require.NoError(s.T(), scimactions.CheckStatus(addResp, http.StatusOK, "PATCH add member to group should return 200"))
	}

	groupPrincipal := fmt.Sprintf("%s_group://%s", authactions.OpenLdap, groupName)
	logrus.Infof("Creating group CRTB for principal %s", groupPrincipal)

	crtb, err := rbacapi.CreateGroupClusterRoleTemplateBinding(s.client, s.cluster.ID, groupPrincipal, string(rbac.ClusterMember))
	require.NoError(s.T(), err, "Should be able to create group CRTB")
	require.NotEmpty(s.T(), crtb.Name)

	foundCRTB, err := rbacapi.GetClusterRoleTemplateBindingsForGroup(s.client, groupPrincipal, s.cluster.ID)
	require.NoError(s.T(), err, "Should find CRTB for group %s", groupPrincipal)
	require.Equal(s.T(), groupPrincipal, foundCRTB.GroupPrincipalName)
	require.Equal(s.T(), s.cluster.ID, foundCRTB.ClusterName)
	require.Equal(s.T(), string(rbac.ClusterMember), foundCRTB.RoleTemplateName)
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMUserPaginationMultiPage() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying multi-page pagination: creating 12 SCIM users")

	const numUsers = 12
	var createdIDs []string
	for i := 0; i < numUsers; i++ {
		_, uid, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
		require.NoError(s.T(), err)
		createdIDs = append(createdIDs, uid)
	}

	b1, err := scimactions.ListSCIMUsersPage(s.scimClient, 1, 5)
	require.NoError(s.T(), err)
	totalResults := int(b1["totalResults"].(float64))
	require.GreaterOrEqual(s.T(), totalResults, numUsers, "totalResults should be at least the number of users we created")
	require.Equal(s.T(), float64(1), b1["startIndex"], "startIndex should be 1")
	require.Equal(s.T(), float64(5), b1["itemsPerPage"], "page 1 should have 5 items")
	resources1, _ := b1["Resources"].([]interface{})
	require.Len(s.T(), resources1, 5, "page 1 should return exactly 5 users")

	b2, err := scimactions.ListSCIMUsersPage(s.scimClient, 6, 5)
	require.NoError(s.T(), err)
	require.Equal(s.T(), float64(totalResults), b2["totalResults"], "totalResults should be consistent across pages")
	require.Equal(s.T(), float64(6), b2["startIndex"])
	require.Equal(s.T(), float64(5), b2["itemsPerPage"])
	resources2, _ := b2["Resources"].([]interface{})
	require.Len(s.T(), resources2, 5, "page 2 should return exactly 5 users")

	b3, err := scimactions.ListSCIMUsersPage(s.scimClient, 11, totalResults)
	require.NoError(s.T(), err)
	require.Equal(s.T(), float64(totalResults), b3["totalResults"], "totalResults should be consistent on page 3")
	require.Equal(s.T(), float64(11), b3["startIndex"])
	resources3, _ := b3["Resources"].([]interface{})
	remaining := totalResults - 10
	require.Len(s.T(), resources3, remaining, "page 3 should return the remaining %d users", remaining)

	seen := map[string]bool{}
	for _, page := range [][]interface{}{resources1, resources2, resources3} {
		for _, item := range page {
			user, _ := item.(map[string]interface{})
			id, _ := user["id"].(string)
			require.False(s.T(), seen[id], "user id %s appears on multiple pages", id)
			seen[id] = true
		}
	}

	for _, id := range createdIDs {
		require.True(s.T(), seen[id], "created user %s should appear in paginated results", id)
	}
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMUserRoleBindingsWork() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Creating SCIM user A with cluster-member CRTB")

	_, userIDA, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	mgmtUserA, err := s.client.Management.User.ByID(userIDA)
	require.NoError(s.T(), err, "Should be able to fetch Rancher user for SCIM user %s", userIDA)

	crtbObjA := &cattlev3.ClusterRoleTemplateBinding{
		ObjectMeta:       metav1.ObjectMeta{Namespace: s.cluster.ID, GenerateName: "crtb-"},
		ClusterName:      s.cluster.ID,
		UserName:         mgmtUserA.ID,
		RoleTemplateName: string(rbac.ClusterMember),
	}
	_, err = extrbacapi.CreateClusterRoleTemplateBinding(s.client, crtbObjA)
	require.NoError(s.T(), err, "Should be able to create CRTB for SCIM user %s", userIDA)

	crtbsA, err := rbacapi.VerifyClusterRoleTemplateBindingForUser(s.client, mgmtUserA.ID, 1)
	require.NoError(s.T(), err, "User A should have exactly 1 CRTB")
	require.Equal(s.T(), s.cluster.ID, crtbsA[0].ClusterName)
	require.Equal(s.T(), string(rbac.ClusterMember), crtbsA[0].RoleTemplateName)

	logrus.Info("Creating SCIM user B without any CRTB")

	_, userIDB, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	mgmtUserB, err := s.client.Management.User.ByID(userIDB)
	require.NoError(s.T(), err)

	_, err = rbacapi.VerifyClusterRoleTemplateBindingForUser(s.client, mgmtUserB.ID, 0)
	require.NoError(s.T(), err, "User B should have no CRTBs")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMUsersAsClusterMembers() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying SCIM users can be assigned as cluster members via CRTB")

	const numUsers = 3
	for i := 0; i < numUsers; i++ {
		logrus.Infof("Creating SCIM cluster member %d", i+1)

		_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
		require.NoError(s.T(), err)

		mgmtUser, err := s.client.Management.User.ByID(userID)
		require.NoError(s.T(), err, "Rancher user %s should exist after SCIM create", userID)

		crtbObj := &cattlev3.ClusterRoleTemplateBinding{
			ObjectMeta:       metav1.ObjectMeta{Namespace: s.cluster.ID, GenerateName: "crtb-"},
			ClusterName:      s.cluster.ID,
			UserName:         mgmtUser.ID,
			RoleTemplateName: string(rbac.ClusterMember),
		}
		_, err = extrbacapi.CreateClusterRoleTemplateBinding(s.client, crtbObj)
		require.NoError(s.T(), err, "Should be able to create CRTB for SCIM user %s", userID)
		_, err = rbacapi.VerifyClusterRoleTemplateBindingForUser(s.client, mgmtUser.ID, 1)
		require.NoError(s.T(), err, "Should find exactly 1 CRTB for SCIM user %s", userID)
	}
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMDeleteGroup() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	deleteResp, err := s.scimClient.Groups().Delete(groupID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(deleteResp, http.StatusNoContent, "DELETE /Groups/{id} should return 204"))

	err = scimactions.WaitForSCIMResourceDeletion(func() (int, error) {
		resp, pollErr := s.scimClient.Groups().ByID(groupID)
		if pollErr != nil {
			return 0, nil
		}
		return resp.StatusCode, nil
	})
	require.NoError(s.T(), err, "Group %s should return 404 after DELETE", groupID)
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMFilterGroupByDisplayName() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying GET /Groups?filter=displayName eq")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	params := url.Values{}
	params.Set("filter", fmt.Sprintf("displayName eq %q", groupName))

	filterResp, err := s.scimClient.Groups().List(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(filterResp, http.StatusOK, "Filtered GET /Groups should return 200"))

	body, err := scimactions.DecodeJSONBody(filterResp)
	require.NoError(s.T(), err)

	groupResources, _ := body["Resources"].([]interface{})
	require.Len(s.T(), groupResources, 1, "Filter should return exactly 1 group")

	firstGroup, _ := groupResources[0].(map[string]interface{})
	require.Equal(s.T(), groupName, firstGroup["displayName"], "Returned group displayName should match filter")
	require.Equal(s.T(), groupID, firstGroup["id"])
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMGetGroupByIDExcludeMembersAttribute() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	_, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	params := url.Values{}
	params.Set("excludedAttributes", "members")

	resp, err := s.scimClient.Groups().ByIDWithQuery(groupID, params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(resp, http.StatusOK, "GET /Groups/{id}?excludedAttributes=members should return 200"))

	body, err := scimactions.DecodeJSONBody(resp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), groupID, body["id"])
	_, hasMembersField := body["members"]
	require.False(s.T(), hasMembersField, "members field should be absent when excludedAttributes=members")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchGroupReplaceExternalID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH replace externalId for group")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	newExternalID := "ext-" + groupName

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "replace", "externalId", newExternalID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH replace externalId should return 200"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), newExternalID, body["externalId"], "externalId should be updated after PATCH replace")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchGroupAddExternalID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH op:add externalId for group is treated as replace")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	newExternalID := "ext-add-" + groupName

	patchResp, err := scimactions.PatchGroup(s.scimClient, groupID, "add", "externalId", newExternalID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH op:add externalId should return 200 (treated as replace)"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), newExternalID, body["externalId"], "externalId should be updated after PATCH op:add")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchUserReplaceExternalID() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH replace externalId for user")

	userName, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	newExternalID := "ext-" + userName

	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "externalId", newExternalID)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH replace externalId should return 200"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), newExternalID, body["externalId"], "externalId should be updated after PATCH replace")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMPatchUserReplacePrimaryEmail() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PATCH replace primary email for user")

	userName, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	newEmail := userName + "@example.com"

	patchResp, err := scimactions.PatchUser(s.scimClient, userID, "replace", "emails[primary eq true].value", newEmail)
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(patchResp, http.StatusOK, "PATCH replace primary email should return 200"))

	body, err := scimactions.DecodeJSONBody(patchResp)
	require.NoError(s.T(), err)

	emails, _ := body["emails"].([]interface{})
	require.Len(s.T(), emails, 1, "User should have exactly 1 email after PATCH")
	email, _ := emails[0].(map[string]interface{})
	require.Equal(s.T(), newEmail, email["value"], "Primary email value should be updated")
	require.Equal(s.T(), true, email["primary"], "Email should be marked as primary")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMUpdateGroup() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PUT /Groups/{id}")

	groupName, groupID, err := scimactions.CreateSCIMGroup(s.scimClient, subSession, "")
	require.NoError(s.T(), err)

	newExternalID := "ext-" + groupName
	updateResp, err := s.scimClient.Groups().Update(groupID, scimclient.Group{
		Schemas:     []string{scimclient.SCIMSchemaGroup},
		ID:          groupID,
		DisplayName: groupName,
		ExternalID:  newExternalID,
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(updateResp, http.StatusOK, "PUT /Groups/{id} should return 200"))

	body, err := scimactions.DecodeJSONBody(updateResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), groupID, body["id"])
	require.Equal(s.T(), groupName, body["displayName"])
	require.Equal(s.T(), newExternalID, body["externalId"], "externalId should be updated after PUT")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMUpdateUser() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PUT /Users/{id}")

	userName, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err)

	newExternalID := "ext-" + userName
	updateResp, err := s.scimClient.Users().Update(userID, scimclient.User{
		Schemas:    []string{scimclient.SCIMSchemaUser},
		UserName:   userName,
		ExternalID: newExternalID,
		Active:     scimclient.BoolPtr(true),
	})
	require.NoError(s.T(), err)
	require.NoError(s.T(), scimactions.CheckStatus(updateResp, http.StatusOK, "PUT /Users/{id} should return 200"))

	body, err := scimactions.DecodeJSONBody(updateResp)
	require.NoError(s.T(), err)
	require.Equal(s.T(), userID, body["id"])
	require.Equal(s.T(), userName, body["userName"])
	require.Equal(s.T(), newExternalID, body["externalId"], "externalId should be updated after PUT")
}

func (s *SCIMOpenLDAPCRUDTestSuite) TestSCIMUserProjectRoleBinding() {
	subSession := s.session.NewSession()
	defer subSession.Cleanup()

	logrus.Info("Verifying PRTB for SCIM user as project-owner")

	_, userID, err := scimactions.CreateSCIMUser(s.scimClient, subSession, "", false)
	require.NoError(s.T(), err, "Should be able to create SCIM user")

	mgmtUser, err := s.client.Management.User.ByID(userID)
	require.NoError(s.T(), err, "Rancher user %s should exist after SCIM create", userID)

	project, err := projectapi.CreateProjectWithTemplate(s.client, s.cluster.ID, projectapi.NewProjectTemplate(s.cluster.ID))
	require.NoError(s.T(), err, "Should be able to create a project in cluster %s", s.cluster.ID)

	prtbNamespace := project.Status.BackingNamespace
	require.NoError(s.T(), authactions.WaitForNamespaceReady(s.client, prtbNamespace),
		"Project backing namespace %s should be ready before creating PRTB", prtbNamespace)

	projectName := fmt.Sprintf("%s:%s", project.Namespace, project.Name)

	prtbObj := &cattlev3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      namegen.AppendRandomString("prtb-"),
			Namespace: prtbNamespace,
		},
		ProjectName:      projectName,
		UserName:         mgmtUser.ID,
		RoleTemplateName: string(rbac.ProjectOwner),
	}

	prtb, err := extrbacapi.CreateProjectRoleTemplateBinding(s.client, prtbObj)
	require.NoError(s.T(), err, "Should be able to create PRTB for SCIM user %s", userID)
	require.NotEmpty(s.T(), prtb.Name)

	prtbs, err := rbacapi.VerifyProjectRoleTemplateBindingForUser(s.client, mgmtUser.ID, 1)
	require.NoError(s.T(), err, "Should find exactly 1 PRTB for SCIM user %s", userID)
	require.Equal(s.T(), projectName, prtbs[0].ProjectName, "PRTB should reference the correct project")
	require.Equal(s.T(), string(rbac.ProjectOwner), prtbs[0].RoleTemplateName, "PRTB role should be project-owner")
	require.Equal(s.T(), mgmtUser.ID, prtbs[0].UserName, "PRTB should be bound to the correct user")
}

func TestSCIMOpenLDAPCRUDSuite(t *testing.T) {
	suite.Run(t, new(SCIMOpenLDAPCRUDTestSuite))
}
