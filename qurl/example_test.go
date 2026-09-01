package qurl_test

import (
	"context"
	"encoding/json"
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

func ExampleResourceHandle_AuthorizeContentRequest() {
	ctx := context.Background()
	handle, err := qurl.EnterPortal(ctx, "https://example.qurl.site/q/example")
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, handle.ResourceURL, nil)
	if err != nil {
		panic(err)
	}
	if err := handle.AuthorizeContentRequest(req); err != nil {
		panic(err)
	}
	client := &http.Client{
		// Keep Jar nil so it cannot append a second qurl_vsession cookie after
		// AuthorizeContentRequest runs.
		CheckRedirect: handle.CheckContentRedirect,
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
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

func ExampleClient_RevokePortal() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	portal, err := client.ResourceByID(exampleResourcePublicKey).CreatePortal(context.Background(), qurl.ValidFor(time.Hour))
	if err != nil {
		panic(err)
	}

	// Revoke by the two ids the create call returned. Revoking a portal that
	// is no longer active fails with ErrPortalRevoked.
	err = client.RevokePortal(context.Background(), portal.ResourceID, portal.QURLID)
	if err != nil {
		panic(err)
	}
}

func ExampleResolveRegisteredAgentConnectorResource() {
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	_, binding, err := qurl.ConnectAgentRuntime(ctx, store, qurl.WithAgentRuntimeOfflineOpen())
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
	request, err := qurl.NewNativeConnectorResourceRequest("prod-dashboard", "")
	if err != nil {
		panic(err)
	}
	result, err := qurl.ResolveRegisteredAgentConnectorResource(ctx, binding, request)
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

func ExampleClient_RegisteredAgentResourceHTTPDoer() {
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	client, err := qurl.OpenRegisteredAgent(ctx, store)
	if err != nil {
		panic(err)
	}
	doer, err := client.RegisteredAgentResourceHTTPDoer()
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.layerv.ai/v1/resources", nil)
	if err != nil {
		panic(err)
	}
	resp, err := doer.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}

func ExamplePrepareLiveNativeSessionOperation() {
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	_, binding, err := qurl.ConnectAgentRuntime(ctx, store)
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
	privateKey := binding.TakeDeviceStaticPrivateKey()
	defer clear(privateKey)
	request, err := qurl.NewNativeConnectorResourceRequest("prod-dashboard", "")
	if err != nil {
		panic(err)
	}
	connector, err := qurl.ResolveRegisteredAgentConnectorResource(ctx, binding, request)
	if err != nil {
		panic(err)
	}
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	operation, recoveryEndpoint, err := qurl.PrepareLiveNativeSessionOperation(ctx, binding, privateKey,
		qurl.NativeSessionOperationInput{
			PreparedAtMillis: now.UnixMilli(), ExpiresAtMillis: now.Add(20 * time.Minute).UnixMilli(),
			OwnerID:             "account-owner",
			ProtectedResourceID: connector.Resource.ResourceID, ResourceID: connector.Resource.KnockResourceID,
			RunAttempt: 1, RunID: runID,
		})
	if err != nil {
		panic(err)
	}
	recordJSON, err := json.Marshal(struct {
		Operation        *qurl.NativeSessionOperation `json:"operation"`
		RecoveryEndpoint qurl.NHPUDPEndpoint          `json:"recovery_endpoint"`
	}{Operation: operation, RecoveryEndpoint: recoveryEndpoint})
	if err != nil {
		panic(err)
	}

	// Atomically persist recordJSON before passing operation to
	// KnockRegisteredAgent. Restore its recovery endpoint and pass the decoded
	// endpoint to RecoverNativeSessionOperation after an ambiguous result. If
	// recovery returns NativeSessionOperationUnexpectedAdmissionError, its
	// nonnil result carries UnexpectedAdmission; persist that receipt as MAPPED
	// before retrying recovery.
	_ = recordJSON
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

	// Keep QURLID to revoke this one link later, without disturbing the
	// resource's others: client.RevokePortal(ctx, resourceID, access.QURLID).
	// Like Link, it is not retrievable after this call.
	fmt.Println(access.Link, access.QURLID)
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
	_, binding, err := qurl.ConnectAgentRuntime(ctx, store,
		qurl.WithAgentRuntimeEnrollmentCredential(enrollmentCredentialFromInstaller()),
		qurl.WithAgentRuntimeMetadata("connector-host", "1.0.0"),
		qurl.WithAgentRuntimeHeadlessEnrollment(),
	)
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
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

func ExampleRecoverAgentRuntimeWithCredentialProvider() {
	// Resolve account authority only when validated state needs the Hub. A pure
	// cell resume or durable post-recovery assignment refresh does not ask the
	// provider for a credential.
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
	client, binding, err := qurl.RecoverAgentRuntimeWithCredentialProvider(ctx, func(context.Context) (string, error) {
		return recoveryCredentialFromOperator(), nil
	}, store, qurl.WithAgentRuntimeRecoveryHub(hub))
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
	_, _ = client, binding
}

func ExampleCredentialRecoveredAssignmentRefreshRequiredError() {
	err := &qurl.CredentialRecoveredAssignmentRefreshRequiredError{AgentID: "agent-example"}
	if errors.Is(err, qurl.ErrCredentialRecoveredAssignmentRefreshRequired) {
		// The replacement credential is already durable. Resume only the
		// mandatory Hub assignment refresh with RefreshAgentRuntime.
		fmt.Println("refresh required for", err.AgentID)
	}
	// Output: refresh required for agent-example
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
	_, binding, _ := qurl.ConnectAgentRuntime(context.Background(), store,
		qurl.WithAgentRuntimeEnrollmentCredential("lv_enrollment_AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"),
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
	//
	// Enrollment and lease renewal authenticate against the Hub trust root,
	// which comes from your deployment file: set QURL_DEPLOYMENT to the file
	// from LayerV setup, or pass WithAgentRuntimeHub. GA builds will ship the
	// trust root embedded. A completed registration with a live lease reopens
	// without one.
	ctx := context.Background()
	store, err := qurl.OpenFileAgentState("/var/lib/layerv/qurl/agent-state.json")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	// Enrollment defaults to the emailed one-time code, so a runtime that can
	// reach its mailbox supplies a provider. Later starts never use either.
	_, binding, err := qurl.ConnectAgentRuntime(ctx, store,
		qurl.WithAgentRuntimeEnrollmentCredential(enrollmentCredentialFromInstaller()),
		qurl.WithAgentRuntimeOTPProvider(readOneTimeCodeFromMailbox),
		qurl.WithAgentRuntimeMetadata("connector-host", "1.0.0"),
	)
	if err != nil {
		panic(err)
	}
	defer binding.Destroy()
	request, err := qurl.NewNativeConnectorResourceRequest("prod-dashboard", "")
	if err != nil {
		panic(err)
	}
	connector, err := qurl.ResolveRegisteredAgentConnectorResource(ctx, binding, request)
	if err != nil {
		panic(err)
	}
	devicePrivateKey := binding.TakeDeviceStaticPrivateKey()
	defer clear(devicePrivateKey)
	runID, err := qurl.NewCycleRunID()
	if err != nil {
		panic(err)
	}
	admission, err := qurl.KnockRegisteredAgent(ctx, binding, devicePrivateKey,
		connector.Resource.KnockResourceID,
		qurl.NativeKnockOptions{ProtectedResourceID: exampleResourcePublicKey, RunID: runID, RunAttempt: 1},
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(admission.ResourceHost)

	// After this exact serving session has stopped and drained, retire it while
	// the device key and opaque in-memory receipt are still available. Retry an
	// ambiguous retirement with the same receipt; defer clears the key only
	// after this lifecycle operation finishes.
	if _, err := qurl.RetireRegisteredAgentSession(ctx, binding, devicePrivateKey, admission.SessionReceipt); err != nil {
		panic(err)
	}
}
