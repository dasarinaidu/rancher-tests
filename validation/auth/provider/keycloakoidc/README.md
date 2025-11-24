## Keycloak OIDC Authentication Tests

This package contains tests for Keycloak OIDC authentication provider functionality in Rancher.

## Table of Contents

- [Keycloak OIDC Authentication Tests](#keycloak-oidc-authentication-tests)
- [Table of Contents](#table-of-contents)
- [Test Coverage](#test-coverage)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
    - [Rancher Configuration](#rancher-configuration)
    - [Keycloak OIDC Test Configuration](#keycloak-oidc-test-configuration)
    - [Group Structure](#group-structure)
    - [Running the Tests](#running-the-tests)

## Test Coverage

These tests validate:

- Authentication provider enable/disable functionality
- User authentication with different access modes (unrestricted, restricted, required)
- Group membership and permissions
- Cluster and project role bindings with OIDC groups
- Access control for authorized and unauthorized users
- OAuth2/OIDC flow with Keycloak
- Client secret management

## Prerequisites

- Keycloak server must be configured and accessible
- Rancher instance must be configured
- Test users and groups must exist in your Keycloak realm with the following structure:
  ```
  Realm: rancher
    Users:
      - testuser1 (password: Burritos2025!)
      - testuser2 (password: Burritos2025!)
      - testuser3 (password: Burritos2025!)
      - testuser4 (password: Burritos2025!)
    Groups:
      - testgroup1 (contains: testuser2, testuser3, testuser4)
  ```

## Configuration

### Rancher Configuration

```yaml
rancher:
  host: "rancher_server_address"
  adminToken: "rancher_admin_token"
  clusterName: "cluster_to_run_tests_on"
  insecure: true
  cleanup: false
```

### Keycloak OIDC Test Configuration

Add the test user and group mappings under keycloakOIDC and keycloakOIDCAuthInput:

```yaml
keycloakOIDC:
  clientId: "rancher"
  clientSecret: "<your-client-secret>"
  issuer: "https://keycloakqatest.qa.rancher.space:8443/realms/rancher"
  authEndpoint: "https://keycloakqatest.qa.rancher.space:8443/realms/rancher/protocol/openid-connect/auth"
  rancherUrl: "https://<rancher-ip>/verify-auth"
  # privateKey and certificate are optional - will be auto-generated if not provided
  groupSearchEnabled: true
  scopes: "openid profile email"
  usernameClaim: "preferred_username"
  groupsClaim: "groups"
  accessMode: "unrestricted"
  users:
    admin:
      username: "<admin-username>"
      password: "<admin-user-password>"

keycloakOIDCAuthInput:
  standardUser: "testuser1"
  group: "testgroup1"
  users:
    - username: "testuser2"
      password: "Burritos2025!"
    - username: "testuser3"
      password: "Burritos2025!"
    - username: "testuser4"
      password: "Burritos2025!"
  projectGroup: "testgroup1"
  projectUsers:
    - username: "testuser2"
      password: "Burritos2025!"
    - username: "testuser3"
      password: "Burritos2025!"
  allowedUsers:
    - username: "testuser2"
      password: "Burritos2025!"
    - username: "testuser3"
      password: "Burritos2025!"
  disallowedUsers:
    - username: "testuser1"
      password: "Burritos2025!"
```

### Group Structure

- `testgroup1`: Base group containing testuser2, testuser3, testuser4
- Users in this group will have group membership validated through OIDC claims

### Keycloak Configuration Notes

1. **Client Configuration**:
   - Create a confidential client in Keycloak
   - Set Valid Redirect URIs: `https://<rancher-url>/verify-auth`
   - Set Web Origins: `https://<rancher-url>`
   - Enable "Client authentication"
   - Copy the client secret

2. **Realm Configuration**:
   - Create users with passwords (disable password temporary flag)
   - Create groups and add users to groups
   - Configure group claims in client mappers

3. **Client Mappers** (for group support):
   - Add a "Group Membership" mapper
   - Token Claim Name: `groups`
   - Full group path: OFF
   - Add to ID token: ON
   - Add to access token: ON
   - Add to userinfo: ON

### Running the Tests

**Run Keycloak OIDC Authentication Tests**

Your GO suite should be set to `-run ^TestKeycloakOIDCAuthProviderSuite$`

**Example:**

```bash
gotestsum --format standard-verbose --packages=github.com/rancher/tests/validation/auth/provider/keycloakoidc --junitfile results.xml -- -timeout=60m -tags=validation -v -run ^TestKeycloakOIDCAuthProviderSuite$
```

## Test Scenarios

### Basic Tests
1. **TestEnableKeycloakOIDC**: Verifies that Keycloak OIDC can be enabled and configuration is stored correctly
2. **TestDisableKeycloakOIDC**: Verifies that Keycloak OIDC can be disabled and secrets are cleaned up

### Access Mode Tests
3. **TestAllowAnyUserAccessMode**: Tests unrestricted mode where all valid users can login
4. **TestAllowClusterAndProjectMembersAccessMode**: Tests restricted mode where only cluster/project members can login
5. **TestRestrictedAccessModeAuthorizedUsersCanLogin**: Tests required mode for authorized users
6. **TestRestrictedAccessModeUnauthorizedUsersCannotLogin**: Tests required mode blocks unauthorized users

### Group Membership Tests
7. **TestRefreshGroup**: Tests group membership refresh and role assignment
8. **TestGroupMembershipProjectAccess**: Tests project access through group membership
9. **TestRestrictedAccessModeClusterAndProjectBindings**: Tests role bindings with groups

## Troubleshooting

### Common Issues

1. **OAuth Flow Failures**: Ensure redirect URIs are correctly configured in Keycloak
2. **Group Claims Not Working**: Verify client mappers are configured properly
3. **Certificate Errors**: Ensure Keycloak uses valid certificates or provide CA cert
4. **Login Timeout**: Check network connectivity between Rancher and Keycloak

### Debug Logs

Enable debug logging in Rancher to see detailed OAuth flow:
```bash
kubectl -n cattle-system logs -f deployment/rancher --tail=100
```

## Additional Notes

- The tests automatically generate self-signed certificates if not provided
- Group membership is determined by the `groups` claim in OIDC tokens
- Access modes follow the same patterns as other auth providers (LDAP, AD)
- All tests clean up resources in their teardown phases
