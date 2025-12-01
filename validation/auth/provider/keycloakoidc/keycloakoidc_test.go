//go:build (validation || infra.any || cluster.any || extended) && !sanity && !stress

package keycloakoidc

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	managementv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/clients/rancher/auth"
	v3 "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	v1 "github.com/rancher/shepherd/clients/rancher/v1"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/rancher/shepherd/extensions/defaults"
	"github.com/rancher/shepherd/extensions/users"
	"github.com/rancher/shepherd/pkg/config"
	"github.com/rancher/shepherd/pkg/session"
	krbac "github.com/rancher/tests/actions/kubeapi/rbac"
	"github.com/rancher/tests/actions/projects"
	"github.com/rancher/tests/actions/rbac"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
)

type KeycloakOIDCAuthProviderSuite struct {
	suite.Suite
	session    *session.Session
	client     *rancher.Client
	cluster    *v3.Cluster
	authConfig *AuthConfig
	adminUser  *v3.User
}

func (k *KeycloakOIDCAuthProviderSuite) SetupSuite() {
	k.session = session.NewSession()

	client, err := rancher.NewClient("", k.session)
	require.NoError(k.T(), err, "Failed to create Rancher client")
	k.client = client

	logrus.Info("Loading auth configuration from config file")
	k.authConfig = new(AuthConfig)
	config.LoadConfig(ConfigurationFileKey, k.authConfig)
	require.NotNil(k.T(), k.authConfig, "Auth configuration is not provided")

	logrus.Info("Getting cluster name from the config file")
	clusterName := client.RancherConfig.ClusterName
	require.NotEmpty(k.T(), clusterName, "Cluster name should be set")

	clusterID, err := clusters.GetClusterIDByName(k.client, clusterName)
	require.NoError(k.T(), err, "Error getting cluster ID for cluster: %s", clusterName)

	k.cluster, err = k.client.Management.Cluster.ByID(clusterID)
	require.NoError(k.T(), err, "Failed to retrieve cluster by ID: %s", clusterID)

	// Load the Shepherd Keycloak OIDC config (contains clientId, issuer, accessMode, etc.)
	if client.Auth.KeycloakOIDC == nil || client.Auth.KeycloakOIDC.Config == nil {
		require.Fail(k.T(), "Keycloak OIDC configuration not found in shepherd config")
	}

	shepherdConfig := client.Auth.KeycloakOIDC.Config

	// Merge Shepherd config into AuthConfig (gives us the base OIDC settings)
	if k.authConfig.ClientID == "" {
		k.authConfig.ClientID = shepherdConfig.ClientID
	}
	if k.authConfig.ClientSecret == "" {
		k.authConfig.ClientSecret = shepherdConfig.ClientSecret
	}
	if k.authConfig.Issuer == "" {
		k.authConfig.Issuer = shepherdConfig.Issuer
	}
	if k.authConfig.AuthEndpoint == "" {
		k.authConfig.AuthEndpoint = shepherdConfig.AuthEndpoint
	}
	if k.authConfig.RancherURL == "" {
		k.authConfig.RancherURL = shepherdConfig.RancherURL
	}
	if k.authConfig.AccessMode == "" {
		k.authConfig.AccessMode = shepherdConfig.AccessMode
	}
	if k.authConfig.Scopes == "" {
		k.authConfig.Scopes = "openid profile email"
		logrus.Info("Using default scopes: openid profile email")
	} else {
		// Ensure openid is present in scopes
		if !strings.Contains(k.authConfig.Scopes, "openid") {
			k.authConfig.Scopes = "openid " + k.authConfig.Scopes
			logrus.Infof("Added 'openid' to scopes: %s", k.authConfig.Scopes)
		}
	}
	if k.authConfig.UsernameClaim == "" {
		k.authConfig.UsernameClaim = shepherdConfig.UsernameClaim
	}
	if k.authConfig.GroupsClaim == "" {
		k.authConfig.GroupsClaim = shepherdConfig.GroupsClaim
	}
	k.authConfig.GroupSearchEnabled = shepherdConfig.GroupSearchEnabled
	if k.authConfig.PrivateKey == "" {
		k.authConfig.PrivateKey = shepherdConfig.PrivateKey
	}
	if k.authConfig.Certificate == "" {
		k.authConfig.Certificate = shepherdConfig.Certificate
	}

	// Set up admin user from Shepherd config
	if shepherdConfig.Users != nil && shepherdConfig.Users.Admin != nil {
		logrus.Info("Setting up admin user credentials from Shepherd configuration")
		k.adminUser = &v3.User{
			Username: shepherdConfig.Users.Admin.Username,
			Password: shepherdConfig.Users.Admin.Password,
		}
	} else {
		require.Fail(k.T(), "Admin user not defined in Shepherd keycloakOIDC config")
	}

	// Apply defaults and validate scopes
	if k.authConfig.Scopes == "" {
		k.authConfig.Scopes = "openid profile email"
		logrus.Info("Using default scopes: openid profile email")
	} else {
		// Ensure openid is present in scopes
		if !strings.Contains(k.authConfig.Scopes, "openid") {
			k.authConfig.Scopes = "openid " + k.authConfig.Scopes
			logrus.Infof("Added 'openid' to scopes: %s", k.authConfig.Scopes)
		}
	}

	// Apply defaults for other optional fields
	if k.authConfig.UsernameClaim == "" {
		k.authConfig.UsernameClaim = "preferred_username"
	}
	if k.authConfig.GroupsClaim == "" {
		k.authConfig.GroupsClaim = "groups"
	}
	if k.authConfig.AccessMode == "" {
		k.authConfig.AccessMode = "unrestricted"
	}

	// Validate required fields
	require.NotEmpty(k.T(), k.authConfig.ClientID, "ClientID must be provided")
	require.NotEmpty(k.T(), k.authConfig.ClientSecret, "ClientSecret must be provided")
	require.NotEmpty(k.T(), k.authConfig.Issuer, "Issuer must be provided")
	require.NotEmpty(k.T(), k.authConfig.AccessMode, "AccessMode must be provided")
	require.NotEmpty(k.T(), k.authConfig.Scopes, "Scopes must be provided")
	require.Contains(k.T(), k.authConfig.Scopes, "openid", "Scopes must contain 'openid'")

	logrus.Infof("Final configuration - ClientID: %s, Issuer: %s, Scopes: %s, AccessMode: %s",
		k.authConfig.ClientID, k.authConfig.Issuer, k.authConfig.Scopes, k.authConfig.AccessMode)

	logrus.Info("Enabling Keycloak OIDC authentication for test suite")
	rancherHost := client.RancherConfig.Host

	// Build oidcConfig for API calls - only include fields that the API expects
	oidcConfig := map[string]interface{}{
		"type":               "keycloakoidc",
		"clientId":           k.authConfig.ClientID,
		"clientSecret":       k.authConfig.ClientSecret,
		"issuer":             k.authConfig.Issuer,
		"authEndpoint":       k.authConfig.AuthEndpoint,
		"rancherUrl":         k.authConfig.RancherURL,
		"scope":              k.authConfig.Scopes,
		"accessMode":         k.authConfig.AccessMode,
		"groupSearchEnabled": k.authConfig.GroupSearchEnabled,
		"usernameClaim":      k.authConfig.UsernameClaim,
		"groupsClaim":        k.authConfig.GroupsClaim,
	}

	// Only add optional fields if they're not empty
	if k.authConfig.PrivateKey != "" {
		oidcConfig["privateKey"] = k.authConfig.PrivateKey
	}
	if k.authConfig.Certificate != "" {
		oidcConfig["certificate"] = k.authConfig.Certificate
	}

	logrus.Infof("OIDC Config being sent to API: %+v", oidcConfig)

	// Use the two-step API process to enable Keycloak OIDC
	err = EnableKeycloakOIDCWithTestAndApply(client, rancherHost, oidcConfig)
	require.NoError(k.T(), err, "Failed to enable Keycloak OIDC (configureTest + testAndApply)")
}

func (k *KeycloakOIDCAuthProviderSuite) TearDownSuite() {
	if k.client != nil {
		oidcConfig, err := k.client.Management.AuthConfig.ByID(keycloakoidc)
		if err == nil && oidcConfig.Enabled {
			logrus.Info("Disabling Keycloak OIDC authentication after test suite")
			err := k.client.Auth.KeycloakOIDC.Disable()
			if err != nil {
				logrus.WithError(err).Warn("Failed to disable Keycloak OIDC in teardown")
			}
		}
	}
	k.session.Cleanup()
}

func (k *KeycloakOIDCAuthProviderSuite) TestKeycloakOIDCEnabled() {
	subSession := k.session.NewSession()
	defer subSession.Cleanup()

	client, err := k.client.WithSession(subSession)
	require.NoError(k.T(), err, "Failed to create client with new session")

	// Verify Keycloak OIDC is enabled
	oidcConfig, err := waitForKeycloakOIDCEnabled(k.client)
	require.NoError(k.T(), err, "Failed waiting for Keycloak OIDC to be enabled")

	require.True(k.T(), oidcConfig.Enabled, "Keycloak OIDC should be enabled")
	require.Equal(k.T(), authProvCleanupAnnotationValUnlocked, oidcConfig.Annotations[authProvCleanupAnnotationKey], "Annotation should be unlocked")

	// Verify client secret is stored properly
	passwordSecretResp, err := client.Steve.SteveType("secret").ByID(passwordSecretID)
	require.NoError(k.T(), err, "Failed to retrieve password secret")

	passwordSecret := &corev1.Secret{}
	require.NoError(k.T(), v1.ConvertToK8sType(passwordSecretResp.JSONResp, passwordSecret), "Failed to convert secret")

	require.NotEmpty(k.T(), string(passwordSecret.Data["clientsecret"]), "Client secret should not be empty")
}

func (k *KeycloakOIDCAuthProviderSuite) TestDisableKeycloakOIDC() {
	subSession := k.session.NewSession()
	defer subSession.Cleanup()

	client, err := k.client.WithSession(subSession)
	require.NoError(k.T(), err, "Failed to create client with new session")

	// Ensure OIDC is enabled first
	_, err = waitForKeycloakOIDCEnabled(k.client)
	require.NoError(k.T(), err, "Keycloak OIDC should be enabled before testing disable")

	// Disable Keycloak OIDC
	err = client.Auth.KeycloakOIDC.Disable()
	require.NoError(k.T(), err, "Failed to disable Keycloak OIDC")

	// Wait for the annotation to be updated
	oidcConfig, err := waitForAuthProviderAnnotationUpdate(client, authProvCleanupAnnotationValLocked)
	require.NoError(k.T(), err, "Failed waiting for annotation update")

	require.False(k.T(), oidcConfig.Enabled, "Keycloak OIDC should be disabled")
	require.Equal(k.T(), authProvCleanupAnnotationValLocked, oidcConfig.Annotations[authProvCleanupAnnotationKey], "Annotation should be locked")

	// Verify secret is deleted
	_, err = client.Steve.SteveType("secret").ByID(passwordSecretID)
	require.Error(k.T(), err, "Password secret should not exist")
	require.Contains(k.T(), err.Error(), "404", "Should return 404 error")

	// Re-enable for other tests - this requires the two-step process again
	rancherHost := client.RancherConfig.Host
	oidcConfig2 := map[string]interface{}{
		"type":               "keycloakoidc",
		"clientId":           k.authConfig.ClientID,
		"clientSecret":       k.authConfig.ClientSecret,
		"issuer":             k.authConfig.Issuer,
		"authEndpoint":       k.authConfig.AuthEndpoint,
		"rancherUrl":         k.authConfig.RancherURL,
		"scopes":             k.authConfig.Scopes,
		"accessMode":         k.authConfig.AccessMode,
		"groupSearchEnabled": k.authConfig.GroupSearchEnabled,
		"usernameClaim":      k.authConfig.UsernameClaim,
		"groupsClaim":        k.authConfig.GroupsClaim,
	}

	if k.authConfig.PrivateKey != "" {
		oidcConfig2["privateKey"] = k.authConfig.PrivateKey
	}
	if k.authConfig.Certificate != "" {
		oidcConfig2["certificate"] = k.authConfig.Certificate
	}

	err = EnableKeycloakOIDCWithTestAndApply(k.client, rancherHost, oidcConfig2)
	require.NoError(k.T(), err, "Failed to re-enable Keycloak OIDC")
}

func (k *KeycloakOIDCAuthProviderSuite) TestAllowAnyUserAccessMode() {
	subSession, authAdmin, err := setupAuthenticatedTest(k.client, k.session, k.adminUser)
	require.NoError(k.T(), err, "Failed to setup authenticated test")
	defer subSession.Cleanup()

	allUsers := k.authConfig.Users
	err = verifyUserLogins(authAdmin, auth.KeycloakOIDCAuth, allUsers, "unrestricted access mode", true)
	require.NoError(k.T(), err, "All users should be able to login")
}

func (k *KeycloakOIDCAuthProviderSuite) TestRefreshGroup() {
	subSession, authAdmin, err := setupAuthenticatedTest(k.client, k.session, k.adminUser)
	require.NoError(k.T(), err, "Failed to setup authenticated test")
	defer subSession.Cleanup()

	adminGroupPrincipalID := getGroupPrincipalID(k.client, k.authConfig.Groups)
	adminGlobalRole := &managementv3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "grb-",
		},
		GlobalRoleName:     rbac.Admin.String(),
		GroupPrincipalName: adminGroupPrincipalID,
	}

	_, err = krbac.CreateGlobalRoleBinding(authAdmin, adminGlobalRole)
	require.NoError(k.T(), err, "Failed to create admin global role binding")

	err = users.RefreshGroupMembership(authAdmin)
	require.NoError(k.T(), err, "Failed to refresh group membership")

	standardGroupPrincipalID := getGroupPrincipalID(k.client, k.authConfig.ProjectGroup)
	standardGlobalRole := &managementv3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "grb-",
		},
		GlobalRoleName:     rbac.StandardUser.String(),
		GroupPrincipalName: standardGroupPrincipalID,
	}

	_, err = krbac.CreateGlobalRoleBinding(authAdmin, standardGlobalRole)
	require.NoError(k.T(), err, "Failed to create standard global role binding")

	err = users.RefreshGroupMembership(authAdmin)
	require.NoError(k.T(), err, "Failed to refresh group membership")

	for _, userInfo := range k.authConfig.ProjectUsers {
		user := &v3.User{
			Username: userInfo.Username,
			Password: userInfo.Password,
		}
		userClient, err := loginAsAuthUser(authAdmin, auth.KeycloakOIDCAuth, user)
		require.NoError(k.T(), err, "Failed to login user [%v]", userInfo.Username)

		_, err = userClient.Steve.SteveType(clusters.ProvisioningSteveResourceType).List(nil)
		require.NotNil(k.T(), err, "User [%v] should NOT list clusters", userInfo.Username)
		require.Contains(k.T(), err.Error(), "Resource type [provisioning.cattle.io.cluster] has no method GET", "Should indicate insufficient permissions")
	}
}

func (k *KeycloakOIDCAuthProviderSuite) TestGroupMembershipProjectAccess() {
	subSession, authAdmin, err := setupAuthenticatedTest(k.client, k.session, k.adminUser)
	require.NoError(k.T(), err, "Failed to setup authenticated test")
	defer subSession.Cleanup()

	projectResp, _, err := projects.CreateProjectAndNamespaceUsingWrangler(authAdmin, k.cluster.ID)
	require.NoError(k.T(), err, "Failed to create project and namespace")

	groupPrincipalID := getGroupPrincipalID(k.client, k.authConfig.ProjectGroup)

	prtbNamespace := projectResp.Name
	if projectResp.Status.BackingNamespace != "" {
		prtbNamespace = projectResp.Status.BackingNamespace
	}

	projectName := fmt.Sprintf("%s:%s", projectResp.Namespace, projectResp.Name)

	groupPRTBResp, err := rbac.CreateGroupProjectRoleTemplateBinding(authAdmin, projectName, prtbNamespace, groupPrincipalID, rbac.ProjectOwner.String())
	require.NoError(k.T(), err, "Failed to create PRTB")
	require.NotNil(k.T(), groupPRTBResp, "PRTB should be created")

	for _, userInfo := range k.authConfig.ProjectUsers {
		user := &v3.User{
			Username: userInfo.Username,
			Password: userInfo.Password,
		}
		userClient, err := loginAsAuthUser(authAdmin, auth.KeycloakOIDCAuth, user)
		require.NoError(k.T(), err, "Failed to login user [%v]", userInfo.Username)

		newUserClient, err := userClient.ReLogin()
		require.NoError(k.T(), err, "Failed to relogin user [%v]", userInfo.Username)

		projectList, err := newUserClient.Steve.SteveType("management.cattle.io.project").List(nil)
		require.NoError(k.T(), err, "User [%v] should be able to list projects", userInfo.Username)
		require.Greater(k.T(), len(projectList.Data), 0, "User [%v] should see at least 1 project", userInfo.Username)
	}
}

func (k *KeycloakOIDCAuthProviderSuite) TestRestrictedAccessModeClusterAndProjectBindings() {
	subSession, authAdmin, err := setupAuthenticatedTest(k.client, k.session, k.adminUser)
	require.NoError(k.T(), err, "Failed to setup authenticated test")
	defer subSession.Cleanup()

	groupPrincipalID := getGroupPrincipalID(k.client, k.authConfig.Groups)
	_, err = rbac.CreateGroupClusterRoleTemplateBinding(authAdmin, k.cluster.ID, groupPrincipalID, rbac.ClusterMember.String())
	require.NoError(k.T(), err, "Failed to create cluster role binding")

	projectResp, _, err := projects.CreateProjectAndNamespaceUsingWrangler(authAdmin, k.cluster.ID)
	require.NoError(k.T(), err, "Failed to create project")

	prtbNamespace := projectResp.Name
	if projectResp.Status.BackingNamespace != "" {
		prtbNamespace = projectResp.Status.BackingNamespace
	}

	err = waitForNamespaceReady(authAdmin, prtbNamespace, defaults.OneMinuteTimeout)
	require.NoError(k.T(), err, "Namespace should be ready")

	projectName := fmt.Sprintf("%s:%s", projectResp.Namespace, projectResp.Name)

	for _, userInfo := range k.authConfig.ProjectUsers {
		userPrincipalID := getUserPrincipalID(k.client, userInfo.Username)

		userPRTB := &managementv3.ProjectRoleTemplateBinding{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:    prtbNamespace,
				GenerateName: "prtb-",
			},
			ProjectName:       projectName,
			UserPrincipalName: userPrincipalID,
			RoleTemplateName:  rbac.ProjectOwner.String(),
		}

		userPRTBResp, err := krbac.CreateProjectRoleTemplateBinding(authAdmin, userPRTB)
		require.NoError(k.T(), err, "Failed to create PRTB for user [%v]", userInfo.Username)
		require.NotNil(k.T(), userPRTBResp, "PRTB should be created for user [%v]", userInfo.Username)
	}
}

func (k *KeycloakOIDCAuthProviderSuite) TestAllowClusterAndProjectMembersAccessMode() {
	subSession, authAdmin, err := setupAuthenticatedTest(k.client, k.session, k.adminUser)
	require.NoError(k.T(), err, "Failed to setup authenticated test")
	defer subSession.Cleanup()

	groupPrincipalID := getGroupPrincipalID(k.client, k.authConfig.Groups)
	_, err = rbac.CreateGroupClusterRoleTemplateBinding(authAdmin, k.cluster.ID, groupPrincipalID, rbac.ClusterMember.String())
	require.NoError(k.T(), err, "Failed to create cluster role binding")

	projectResp, _, err := projects.CreateProjectAndNamespaceUsingWrangler(authAdmin, k.cluster.ID)
	require.NoError(k.T(), err, "Failed to create project")

	prtbNamespace := projectResp.Name
	if projectResp.Status.BackingNamespace != "" {
		prtbNamespace = projectResp.Status.BackingNamespace
	}
	projectName := fmt.Sprintf("%s:%s", projectResp.Namespace, projectResp.Name)

	projectGroupPrincipalID := getGroupPrincipalID(k.client, k.authConfig.ProjectGroup)

	groupPRTBResp, err := rbac.CreateGroupProjectRoleTemplateBinding(authAdmin, projectName, prtbNamespace, projectGroupPrincipalID, rbac.ProjectOwner.String())
	require.NoError(k.T(), err, "Failed to create PRTB")
	require.NotNil(k.T(), groupPRTBResp, "PRTB should be created")

	allowedUsers := slices.Concat(k.authConfig.Users, k.authConfig.ProjectUsers)
	var allowedPrincipalIDs []string
	allowedPrincipalIDs = append(allowedPrincipalIDs, projectGroupPrincipalID)
	allowedPrincipalIDs = append(allowedPrincipalIDs, groupPrincipalID)

	newAuthConfig, err := updateAccessMode(k.client, AccessModeRestricted, allowedPrincipalIDs)
	require.NoError(k.T(), err, "Failed to update access mode")
	require.Equal(k.T(), AccessModeRestricted, newAuthConfig.AccessMode, "Access mode should be restricted")

	err = verifyUserLogins(authAdmin, auth.KeycloakOIDCAuth, allowedUsers, "restricted access mode", true)
	require.NoError(k.T(), err, "Cluster/project members should be able to login")

	if len(k.authConfig.DisallowedUsers) > 0 {
		err = verifyUserLogins(authAdmin, auth.KeycloakOIDCAuth, k.authConfig.DisallowedUsers, "restricted access mode", false)
		require.NoError(k.T(), err, "Non-members should NOT be able to login")
	}

	_, err = updateAccessMode(k.client, AccessModeUnrestricted, nil)
	require.NoError(k.T(), err, "Failed to rollback access mode")
}

func (k *KeycloakOIDCAuthProviderSuite) TestRestrictedAccessModeAuthorizedUsersCanLogin() {
	subSession, authAdmin, err := setupAuthenticatedTest(k.client, k.session, k.adminUser)
	require.NoError(k.T(), err, "Failed to setup authenticated test")
	defer subSession.Cleanup()

	principalIDs, err := setupRequiredAccessModeTest(k.client, authAdmin, k.cluster.ID, k.authConfig)
	require.NoError(k.T(), err, "Failed to setup required access mode test")

	newAuthConfig, err := updateAccessMode(k.client, AccessModeRequired, principalIDs)
	require.NoError(k.T(), err, "Failed to update access mode")
	require.Equal(k.T(), AccessModeRequired, newAuthConfig.AccessMode, "Access mode should be required")

	err = verifyUserLogins(authAdmin, auth.KeycloakOIDCAuth, k.authConfig.Users, "required access mode", true)
	require.NoError(k.T(), err, "Authorized users should be able to login")

	_, err = updateAccessMode(k.client, AccessModeUnrestricted, nil)
	require.NoError(k.T(), err, "Failed to rollback access mode")
}

func (k *KeycloakOIDCAuthProviderSuite) TestRestrictedAccessModeUnauthorizedUsersCannotLogin() {
	subSession, authAdmin, err := setupAuthenticatedTest(k.client, k.session, k.adminUser)
	require.NoError(k.T(), err, "Failed to setup authenticated test")
	defer subSession.Cleanup()

	principalIDs, err := setupRequiredAccessModeTest(k.client, authAdmin, k.cluster.ID, k.authConfig)
	require.NoError(k.T(), err, "Failed to setup required access mode test")

	newAuthConfig, err := updateAccessMode(k.client, AccessModeRequired, principalIDs)
	require.NoError(k.T(), err, "Failed to update access mode")
	require.Equal(k.T(), AccessModeRequired, newAuthConfig.AccessMode, "Access mode should be required")

	if len(k.authConfig.DisallowedUsers) > 0 {
		err = verifyUserLogins(authAdmin, auth.KeycloakOIDCAuth, k.authConfig.DisallowedUsers, "required access mode", false)
		require.NoError(k.T(), err, "Unauthorized users should NOT be able to login")
	}

	_, err = updateAccessMode(k.client, AccessModeUnrestricted, nil)
	require.NoError(k.T(), err, "Failed to rollback access mode")
}

func TestKeycloakOIDCAuthProviderSuite(t *testing.T) {
	suite.Run(t, new(KeycloakOIDCAuthProviderSuite))
}
