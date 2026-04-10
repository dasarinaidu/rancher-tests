package oidc

import (
	"context"
	"fmt"

	"github.com/rancher/shepherd/clients/rancher"
	oidcauth "github.com/rancher/shepherd/clients/rancher/auth/oidc"
	"github.com/rancher/shepherd/extensions/defaults"
	featuresactions "github.com/rancher/tests/actions/features"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	OIDCClientSecretNamespace            = "cattle-oidc-client-secrets"
	DefaultTokenExpirationSeconds        = 3600
	DefaultRefreshTokenExpirationSeconds = 86400

	RancherDeploymentName      = "rancher"
	RancherDeploymentNamespace = "cattle-system"
)

var oidcClientGVR = schema.GroupVersionResource{
	Group:    oidcauth.OIDCClientGroup,
	Version:  oidcauth.OIDCClientVersion,
	Resource: oidcauth.OIDCClientResource,
}

// ClientSpec is the spec section of the OIDCClient CRD.
type ClientSpec struct {
	RedirectURIs                  []string
	Scopes                        []string
	TokenExpirationSeconds        int
	RefreshTokenExpirationSeconds int
}

// EnableOIDCFeatureFlag enables the oidc-provider feature flag if not already enabled,
// waits for Rancher to restart, and registers DisableOIDCFeatureFlag as a session cleanup function.
func EnableOIDCFeatureFlag(client *rancher.Client) error {
	enabled, err := featuresactions.IsEnabled(client, oidcauth.OIDCProviderFeatureFlag)
	if err != nil {
		return err
	}
	if enabled {
		logrus.Info("[OIDC setup] oidc-provider feature flag is already enabled — skipping restart")
		return nil
	}
	logrus.Info("[OIDC setup] Enabling oidc-provider feature flag — Rancher will restart")
	client.Session.RegisterCleanupFunc(func() error {
		return DisableOIDCFeatureFlag(client)
	})
	if err := featuresactions.UpdateFeatureFlag(client, oidcauth.OIDCProviderFeatureFlag, true); err != nil {
		return err
	}
	return waitForRancherReady(client)
}

// waitForRancherReady polls the Rancher deployment directly via the k8s API (bypassing
// Rancher proxy) until all replicas are updated, ready, and available.
func waitForRancherReady(client *rancher.Client) error {
	logrus.Info("[OIDC setup] Waiting for Rancher to be fully ready (max 5m)")
	k8sClient, err := kubernetes.NewForConfig(client.WranglerContext.RESTConfig)
	if err != nil {
		return fmt.Errorf("building k8s client for readiness check: %w", err)
	}
	return kwait.PollUntilContextTimeout(
		context.Background(), defaults.TenSecondTimeout, defaults.FiveMinuteTimeout, false,
		func(ctx context.Context) (bool, error) {
			d, getErr := k8sClient.AppsV1().Deployments(RancherDeploymentNamespace).
				Get(ctx, RancherDeploymentName, metav1.GetOptions{})
			if getErr != nil {
				logrus.Debugf("[OIDC] Rancher not yet readable: %v", getErr)
				return false, nil
			}
			desired := int32(1)
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			if d.Status.UpdatedReplicas >= desired &&
				d.Status.ReadyReplicas >= desired &&
				d.Status.AvailableReplicas >= desired &&
				d.Status.Replicas == desired {
				logrus.Info("[OIDC setup] Rancher is stable — all replicas ready")
				return true, nil
			}
			return false, nil
		},
	)
}

// DisableOIDCFeatureFlag disables the oidc-provider feature flag.
// Disabling does not trigger a Rancher restart so no wait is needed.
func DisableOIDCFeatureFlag(client *rancher.Client) error {
	logrus.Info("[OIDC teardown] Disabling oidc-provider feature flag")
	disabled := false
	feature, err := client.Management.Feature.ByID(oidcauth.OIDCProviderFeatureFlag)
	if err != nil {
		return fmt.Errorf("fetching oidc-provider feature: %w", err)
	}
	feature.Value = &disabled
	_, err = client.Management.Feature.Update(feature, feature)
	if err != nil {
		return fmt.Errorf("disabling oidc-provider feature flag: %w", err)
	}
	return nil
}

// managementDynamicClient builds a dynamic client targeting the management cluster REST config.
func managementDynamicClient(client *rancher.Client) (dynamic.Interface, error) {
	dynClient, err := dynamic.NewForConfig(client.WranglerContext.RESTConfig)
	if err != nil {
		return nil, fmt.Errorf("building management cluster dynamic client: %w", err)
	}
	return dynClient, nil
}

// CreateOIDCClient creates an OIDCClient CRD on the management cluster if it does not already exist.
func CreateOIDCClient(client *rancher.Client, name string, spec ClientSpec) error {
	logrus.Infof("[OIDC setup] Creating OIDCClient CRD %q on management cluster", name)
	if spec.TokenExpirationSeconds == 0 {
		spec.TokenExpirationSeconds = DefaultTokenExpirationSeconds
	}
	if spec.RefreshTokenExpirationSeconds == 0 {
		spec.RefreshTokenExpirationSeconds = DefaultRefreshTokenExpirationSeconds
	}
	if len(spec.Scopes) == 0 {
		spec.Scopes = oidcauth.DefaultAutomationScopes
	}

	redirectURIs := make([]interface{}, len(spec.RedirectURIs))
	for i, v := range spec.RedirectURIs {
		redirectURIs[i] = v
	}
	scopes := make([]interface{}, len(spec.Scopes))
	for i, v := range spec.Scopes {
		scopes[i] = v
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": oidcauth.OIDCClientGroup + "/" + oidcauth.OIDCClientVersion,
			"kind":       oidcauth.OIDCClientKind,
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": map[string]interface{}{
				"redirectURIs":                  redirectURIs,
				"scopes":                        scopes,
				"tokenExpirationSeconds":        int64(spec.TokenExpirationSeconds),
				"refreshTokenExpirationSeconds": int64(spec.RefreshTokenExpirationSeconds),
			},
		},
	}
	dynClient, err := managementDynamicClient(client)
	if err != nil {
		return err
	}
	_, err = dynClient.Resource(oidcClientGVR).Create(context.Background(), obj, metav1.CreateOptions{})
	if err != nil {
		if !k8serrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating OIDCClient %q: %w", name, err)
		}
		logrus.Infof("[OIDC setup] OIDCClient %q already exists — skipping creation", name)
		return nil
	}
	logrus.Infof("[OIDC setup] OIDCClient %q created", name)
	client.Session.RegisterCleanupFunc(func() error {
		return DeleteOIDCClient(client, name)
	})
	return nil
}

// WaitForOIDCClientReady polls until status.clientID and status.clientSecrets are populated.
func WaitForOIDCClientReady(client *rancher.Client, name string) (clientID, secretKeyName string, err error) {
	logrus.Infof("[OIDC setup] Waiting for OIDCClient %q status.clientID (max 2m)", name)
	dynClient, err := managementDynamicClient(client)
	if err != nil {
		return "", "", err
	}
	err = kwait.PollUntilContextTimeout(
		context.Background(), defaults.FiveSecondTimeout, defaults.TwoMinuteTimeout, true,
		func(ctx context.Context) (bool, error) {
			obj, getErr := dynClient.Resource(oidcClientGVR).Get(ctx, name, metav1.GetOptions{})
			if getErr != nil {
				logrus.Debugf("[OIDC] OIDCClient %q not yet visible: %v", name, getErr)
				return false, nil
			}
			status, ok := obj.Object["status"].(map[string]interface{})
			if !ok {
				return false, nil
			}
			id, _ := status["clientID"].(string)
			if id == "" {
				return false, nil
			}
			secrets, _ := status["clientSecrets"].(map[string]interface{})
			if len(secrets) == 0 {
				return false, nil
			}
			for k := range secrets {
				secretKeyName = k
				break
			}
			clientID = id
			logrus.Infof("[OIDC] OIDCClient %q ready — clientID=%s secretKey=%s", name, clientID, secretKeyName)
			return true, nil
		},
	)
	if err != nil {
		return "", "", fmt.Errorf("timed out waiting for OIDCClient %q status.clientID: %w", name, err)
	}
	return clientID, secretKeyName, nil
}

// FetchOIDCClientSecret retrieves the client secret from the Kubernetes secret in cattle-oidc-client-secrets.
func FetchOIDCClientSecret(client *rancher.Client, clientID, secretKeyName string) (string, error) {
	logrus.Infof("[OIDC setup] Fetching client secret from cattle-oidc-client-secrets/%s key=%s",
		clientID, secretKeyName)
	secret, err := client.WranglerContext.Core.Secret().Get(
		OIDCClientSecretNamespace, clientID, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting OIDCClient secret %s/%s: %w",
			OIDCClientSecretNamespace, clientID, err)
	}
	value, ok := secret.Data[secretKeyName]
	if !ok || len(value) == 0 {
		return "", fmt.Errorf("key %q not found or empty in secret %s/%s",
			secretKeyName, OIDCClientSecretNamespace, clientID)
	}
	logrus.Infof("[OIDC setup] Client secret retrieved (last 5 chars confirmed via status)")
	return string(value), nil
}

func DeleteOIDCClient(client *rancher.Client, name string) error {
	logrus.Infof("[OIDC teardown] Deleting OIDCClient %q", name)
	dynClient, err := managementDynamicClient(client)
	if err != nil {
		return err
	}
	err = dynClient.Resource(oidcClientGVR).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logrus.Debugf("[OIDC teardown] OIDCClient %q already gone — skipping", name)
			return nil
		}
		return fmt.Errorf("deleting OIDCClient %q: %w", name, err)
	}
	logrus.Infof("[OIDC teardown] OIDCClient %q deleted", name)
	return nil
}
