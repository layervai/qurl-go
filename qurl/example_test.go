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

func ExampleClient_ResolveResource() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	// Either identifier form works: the public-key resource id or the
	// resource's CRID. Open the minted link with EnterPortal.
	access, err := client.ResolveResource(context.Background(), exampleResourcePublicKey, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(access.QURL)
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
	// Assignment, OTP, REG/RAK, and completion travel only over authenticated
	// NHP UDP. Enrollment defaults to a one-time code emailed to the credential's
	// address: whatever reads that mailbox — a service account, an agent with its
	// own address, an operator — returns the code through the provider.
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	// No hub wiring: the SDK ships the trust root for the deployment it was
	// built to talk to. WithAgentRuntimeHub still overrides it when an operator
	// runs their own.
	client, binding, err := qurl.RegisterAgentRuntime(ctx, enrollmentCredentialFromInstaller(), store,
		qurl.WithAgentRuntimeMetadata("connector-host", "1.0.0"),
		qurl.WithAgentRuntimeOTPProvider(readOneTimeCodeFromMailbox),
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

// ExampleWithAgentRuntimeHeadlessEnrollment shows the escape hatch: a runtime
// with no mailbox at all, enrolling with a pre-issued credential and no code.
// Prefer the default OTP path whenever some address can receive the code.
func ExampleWithAgentRuntimeHeadlessEnrollment() {
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	client, binding, err := qurl.RegisterAgentRuntime(ctx, enrollmentCredentialFromInstaller(), store,
		qurl.WithAgentRuntimeMetadata("connector-host", "1.0.0"),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
	)
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
	_, _ = client, binding
}

func ExampleRecoverAgentRuntime() {
	// Recovery is an explicit operator action after the current device API key
	// has been deliberately revoked. Both lifecycle legs use authenticated NHP
	// UDP; the returned Client alone uses HTTPS for later resource CRUD.
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	hub := qurl.HubBootstrap{
		Host:               "hub.nhp.layerv.ai",
		Port:               443,
		ServerPublicKeyB64: configuredHubPublicKeyB64(),
	}
	client, binding, err := qurl.RecoverAgentRuntime(ctx, recoveryCredentialFromOperator(), store,
		qurl.WithAgentRuntimeRecoveryHub(hub),
	)
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
	_, _ = client, binding
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
	defer store.Close()
	_, binding, _ := qurl.RegisterAgentRuntime(context.Background(), "lv_enrollment_AAECAwQFBgcICQoLDA0ODxAREhMUFRYX", store,
		qurl.WithAgentRuntimeHub(qurl.HubBootstrap{
			Host: "hub.nhp.layerv.ai", Port: 443,
			ServerPublicKeyB64: configuredHubPublicKeyB64(),
		}),
		qurl.WithAgentRuntimeOTPProvider(readOneTimeCodeFromMailbox),
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

// readOneTimeCodeFromMailbox stands in for whatever reads the mailbox the code
// was sent to. The challenge carries only bounded, non-secret context.
func readOneTimeCodeFromMailbox(ctx context.Context, challenge qurl.AgentOTPChallenge) (string, error) {
	_, _ = ctx, challenge
	return "12345678", nil
}
func recoveryCredentialFromOperator() string { return "configured-qurl-agent-recovery-credential" }

func ExampleConnectAgentRuntime() {
	// One call on every start. It enrolls the first time, resumes an interrupted
	// enrollment, and afterwards returns the existing registration — renewing an
	// expired lease and following any relocation without being asked.
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	// Enrollment defaults to the emailed one-time code, so a runtime that can
	// reach its mailbox supplies a provider. Later starts never use either.
	client, binding, err := qurl.ConnectAgentRuntime(ctx, store,
		qurl.WithAgentRuntimeEnrollmentCredential(enrollmentCredentialFromInstaller()),
		qurl.WithAgentRuntimeOTPProvider(readOneTimeCodeFromMailbox),
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
