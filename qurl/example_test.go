package qurl_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

const exampleResourcePublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2cTVv5_3eeYCcLLq5ROYCqcmY50HiKZ9ATglIkPnCji1E_S63UMtXba1moR8-Q6EV7oM6zwwh9_j2CDujzXvLA"

func Example() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	resource, err := client.ProtectURL(context.Background(), "https://internal.example.com/dashboard")
	if err != nil {
		panic(err)
	}

	portal, err := resource.CreatePortal(context.Background(), qurl.ValidFor(5*time.Minute))
	if err != nil {
		panic(err)
	}

	fmt.Println(portal.Link)
}

func ExampleClient_ProtectURL() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	resource, err := client.ProtectURL(context.Background(),
		"https://internal.example.com/dashboard",
		qurl.WithAlias("dev-dashboard"),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(resource.ID)
}

func ExampleClient_CreatePortal() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	resource := client.ResourceByID(exampleResourcePublicKey)
	portal, err := resource.CreatePortal(context.Background(),
		qurl.ValidFor(time.Hour),
		qurl.WithLabel("Alice"),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(portal.Link)
}

func ExampleClient_EnsureConnectorResource() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	result, err := client.EnsureConnectorResource(context.Background(), "prod-dashboard")
	if err != nil {
		panic(err)
	}

	fmt.Println(
		result.Resource.ResourceID,
		result.Resource.ConnectorRoutingID,
		result.Resource.KnockResourceID,
		result.FoundExisting,
	)
}

func ExampleOpenClient() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	resource, err := client.ProtectURL(context.Background(), "https://internal.example.com/dashboard")
	if err != nil {
		panic(err)
	}
	_, err = resource.CreatePortal(context.Background(), qurl.ValidFor(5*time.Minute))
	if err != nil {
		panic(err)
	}
}

func ExampleNewClient() {
	credentialFromProtectedState := "lv_test_from_protected_state"
	credentials := qurl.CredentialProviderFunc(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+credentialFromProtectedState)
		return nil
	})
	client, err := qurl.NewClient(credentials)
	if err != nil {
		panic(err)
	}

	resource, err := client.ProtectURL(context.Background(), "https://internal.example.com/dashboard")
	if err != nil {
		panic(err)
	}
	_, err = resource.CreatePortal(context.Background(), qurl.ValidFor(5*time.Minute))
	if err != nil {
		panic(err)
	}
}

func ExampleRegisterAgentRuntime() {
	// The installer supplies one pinned Hub trust root. Assignment, optional OTP,
	// REG/RAK, and completion then travel only over authenticated NHP UDP.
	// The default policy accepts pre-issued/headless key kinds, including the
	// durable qurl:agent kind, and rejects account enrollment.
	ctx := context.Background()
	store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
	hub := qurl.HubBootstrap{
		Host:               "hub.nhp.layerv.ai",
		Port:               62206,
		ServerPublicKeyB64: configuredHubPublicKeyB64(),
	}
	client, binding, err := qurl.RegisterAgentRuntime(ctx, enrollmentCredentialFromInstaller(), store,
		qurl.WithAgentRuntimeHub(hub),
		qurl.WithAgentRuntimeMetadata("connector-host", "1.0.0"),
	)
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
	devicePrivateKey := binding.TakeDeviceStaticPrivateKey()
	defer clear(devicePrivateKey)

	connector, err := client.EnsureConnectorResource(ctx, "prod-dashboard")
	if err != nil {
		panic(err)
	}
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		panic(err)
	}
	admission, err := qurl.KnockRegisteredAgent(ctx, binding, devicePrivateKey,
		connector.Resource.KnockResourceID,
		qurl.NativeKnockOptions{RunID: runID},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(admission.ResourceHost)
}

func ExampleNewSealedFileAgentState() {
	// Production wrappers call a KMS/HSM/attested release API and authenticate
	// every binding field as provider encryption context. They wrap only the
	// exact 32-byte DEK supplied by the SDK, never AgentState JSON.
	var wrapper qurl.AgentStateKeyWrapper = myKMSAgentStateKeyWrapper{}
	store, err := qurl.NewSealedFileAgentState(
		"/var/lib/layerv/qurl/agent_state.sealed.json",
		"aws-kms",
		wrapper,
	)
	if err != nil {
		panic(err)
	}
	_, binding, _ := qurl.RegisterAgentRuntime(context.Background(), "lv_enrollment_AAECAwQFBgcICQoLDA0ODxAREhMUFRYX", store,
		qurl.WithAgentRuntimeHub(qurl.HubBootstrap{
			Host: "hub.nhp.layerv.ai", Port: 62206,
			ServerPublicKeyB64: configuredHubPublicKeyB64(),
		}),
	)
	if binding != nil {
		binding.Destroy()
	}
}

type myKMSAgentStateKeyWrapper struct{}

func (myKMSAgentStateKeyWrapper) WrapKey(_ context.Context, dek []byte, binding qurl.AgentStateKeyBinding) (qurl.WrappedAgentStateKey, error) {
	if len(dek) != 32 {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("expected a 32-byte DEK")
	}
	return callKMSWrap(dek, binding)
}

func (myKMSAgentStateKeyWrapper) UnwrapKey(_ context.Context, wrapped qurl.WrappedAgentStateKey, binding qurl.AgentStateKeyBinding) ([]byte, error) {
	return callKMSUnwrap(wrapped, binding)
}

func callKMSWrap([]byte, qurl.AgentStateKeyBinding) (qurl.WrappedAgentStateKey, error) {
	return qurl.WrappedAgentStateKey{}, errors.New("example KMS adapter")
}

func callKMSUnwrap(qurl.WrappedAgentStateKey, qurl.AgentStateKeyBinding) ([]byte, error) {
	return nil, errors.New("example KMS adapter")
}

func configuredHubPublicKeyB64() string         { return "configured-padded-base64-x25519-key" }
func enrollmentCredentialFromInstaller() string { return "configured-enrollment-credential" }
