package qurl_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/layervai/qurl-go/qurl"
)

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

	resource := client.ResourceByID("r_demo1234567")
	portal, err := resource.CreatePortal(context.Background(),
		qurl.ValidFor(time.Hour),
		qurl.WithLabel("Alice"),
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(portal.Link)
}

func ExampleClient_ConnectorResource() {
	client, err := qurl.OpenClient()
	if err != nil {
		panic(err)
	}

	resource, err := client.ConnectorResource(context.Background(), "prod-dashboard")
	if err != nil {
		panic(err)
	}

	portal, err := resource.CreatePortal(context.Background(), qurl.ValidFor(5*time.Minute))
	if err != nil {
		panic(err)
	}

	fmt.Println(portal.Link)
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

func ExampleBootstrapAgent() {
	setupKey := "lv_temporary_setup_key_from_install_flow"
	_, err := qurl.BootstrapAgent(context.Background(),
		setupKey,
		qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json"),
		qurl.WithAgentID("prod-us-east-1"),
	)
	if err != nil {
		panic(err)
	}
}

func ExampleRegisterAgent() {
	// RegisterAgent is idempotent: the first call enrolls and persists a device
	// credential; later calls load it and return a Client with no network I/O.
	store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
	client, err := qurl.RegisterAgent(context.Background(), "lv_api_key", store)
	if err != nil {
		panic(err)
	}

	resource, err := client.ProtectURL(context.Background(), "https://dashboard.internal.acme.com")
	if err != nil {
		panic(err)
	}
	portal, err := resource.CreatePortal(context.Background(), qurl.ValidFor(time.Hour))
	if err != nil {
		panic(err)
	}
	fmt.Println(portal.Link)
}

func ExampleRegisterAgent_withOTP() {
	// An account key uses email one-time codes. Registration is two-phase and
	// re-entrant: the first call requests a code and returns *OTPPendingError; a
	// second call with WithOTP finishes enrollment.
	ctx := context.Background()
	store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")

	_, err := qurl.RegisterAgent(ctx, "lv_account_key", store)
	var pending *qurl.OTPPendingError
	if errors.As(err, &pending) {
		// LayerV emailed a code to pending.MaskedEmail. Obtain it out of band,
		// then resume. (errors.Is(err, qurl.ErrOTPPending) matches the sentinel.)
		code := readOneTimeCodeFromOperator(pending.MaskedEmail)
		client, err := qurl.RegisterAgent(ctx, "lv_account_key", store, qurl.WithOTP(code))
		if err != nil {
			panic(err)
		}
		_ = client
	} else if err != nil {
		panic(err)
	}
}

func ExampleRegisterAgent_otpProvider() {
	// WithOTPProvider supplies the emailed code from a callback — for a headless
	// agent that reads its own mailbox — so a single RegisterAgent call can both
	// request and consume the code.
	store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
	client, err := qurl.RegisterAgent(context.Background(), "lv_account_key", store,
		qurl.WithOTPProvider(func(ctx context.Context) (string, error) {
			return fetchLatestOneTimeCode(ctx)
		}),
	)
	if err != nil {
		panic(err)
	}
	_ = client
}

func ExampleRegisterAgent_takeover() {
	// A device id that is already enrolled to a different key or agent fails with
	// ErrAgentIdentityConflict. WithTakeover re-binds it — deliberately, since it
	// replaces the prior binding.
	ctx := context.Background()
	store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")

	client, err := qurl.RegisterAgent(ctx, "lv_api_key", store, qurl.WithDeviceID("prod-us-east-1"))
	if errors.Is(err, qurl.ErrAgentIdentityConflict) {
		client, err = qurl.RegisterAgent(ctx, "lv_api_key", store,
			qurl.WithDeviceID("prod-us-east-1"),
			qurl.WithTakeover(),
		)
	}
	if err != nil {
		panic(err)
	}
	_ = client
}

func ExampleRegisterAgent_fromBootstrapAgent() {
	// Migrating from BootstrapAgent: RegisterAgent covers the same pre-issued-key
	// path and additionally returns a ready-to-use Client. WithDeviceID is the
	// RegisterAgent spelling of BootstrapAgent's WithAgentID.
	store := qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json")
	client, err := qurl.RegisterAgent(context.Background(), "lv_temporary_setup_key_from_install_flow", store,
		qurl.WithDeviceID("prod-us-east-1"),
	)
	if err != nil {
		panic(err)
	}
	_ = client
}

// readOneTimeCodeFromOperator and fetchLatestOneTimeCode stand in for the
// caller's own code-retrieval mechanism in the examples above.
func readOneTimeCodeFromOperator(maskedEmail string) string {
	fmt.Printf("enter the code emailed to %s: ", maskedEmail)
	return "123456"
}

func fetchLatestOneTimeCode(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "123456", nil
}
