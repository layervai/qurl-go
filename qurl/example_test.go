package qurl_test

import (
	"context"
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
	bootstrapKey := "lv_temporary_bootstrap_key_from_install_flow"
	_, err := qurl.BootstrapAgent(context.Background(),
		bootstrapKey,
		qurl.FileAgentState("/var/lib/layerv/qurl/agent-state.json"),
		qurl.WithAgentID("prod-us-east-1"),
	)
	if err != nil {
		panic(err)
	}
}
