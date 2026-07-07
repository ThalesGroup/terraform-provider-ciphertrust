package provider

// Live-server create tests for AWS connections.
// These tests call the CipherTrust Manager HTTP API directly (no Terraform
// framework) and do NOT delete the connections afterwards, so the resources
// remain on the server for manual inspection.
//
// They require a reachable CM instance. Set CIPHERTRUST_ADDRESS,
// CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD before running:
//
//	CIPHERTRUST_ADDRESS=https://10.205.96.40 \
//	CIPHERTRUST_USERNAME=admin \
//	CIPHERTRUST_PASSWORD=Asdf@1234 \
//	  go test -run "TestLive_CreateAWSConnection" -v ./internal/provider/...

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// TestLive_CreateAWSConnectionSecretKey creates an AWS connection on the live
// CM server using access_key_id + secret_access_key and leaves it on the server.
func TestCM_AWSConnection_LiveSecretKey(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("skipping TestLive_CreateAWSConnectionSecretKey: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	name := "tf-live-secretkey-" + uuid.New().String()[:8]

	payload, err := json.Marshal(map[string]interface{}{
		"name":              name,
		"access_key_id":     testGetAWSAccessKeyID(),
		"secret_access_key": testGetAWSSecretAccessKey(),
	})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	resp, err := client.PostDataV2(context.Background(), uuid.NewString(), common.URL_AWS_CONNECTION, payload)
	if err != nil {
		t.Fatalf("POST %s failed: %v", common.URL_AWS_CONNECTION, err)
	}

	id := gjson.Get(resp, "id").String()
	if id == "" {
		t.Fatalf("expected non-empty id in response, got: %s", resp)
	}
	gotName := gjson.Get(resp, "name").String()
	if gotName != name {
		t.Errorf("expected name %q, got %q", name, gotName)
	}

	fmt.Printf("✔ TestLive_CreateAWSConnectionSecretKey: created connection id=%s name=%s\n", id, gotName)
	t.Logf("Connection created and left on server: id=%s name=%s", id, gotName)
}

// TestLive_CreateAWSConnectionIAMAnywhere creates an AWS IAM Anywhere connection
// on the live CM server and leaves it on the server.
func TestCM_AWSConnection_LiveIAMAnywhere(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("skipping TestLive_CreateAWSConnectionIAMAnywhere: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	name := "tf-live-iamanywhere-" + uuid.New().String()[:8]

	payload, err := json.Marshal(map[string]interface{}{
		"name":             name,
		"is_role_anywhere": true,
		"iam_role_anywhere": map[string]interface{}{
			"anywhere_role_arn": testIAMAnywhereRoleARN,
			"trust_anchor_arn":  testIAMAnywhereTrustAnchorARN,
			"profile_arn":       testIAMAnywhereProfileARN,
			"certificate":       testIAMAnywhereCert,
			"private_key":       testIAMAnywherePrivateKey,
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	resp, err := client.PostDataV2(context.Background(), uuid.NewString(), common.URL_AWS_CONNECTION, payload)
	if err != nil {
		t.Fatalf("POST %s failed: %v", common.URL_AWS_CONNECTION, err)
	}

	id := gjson.Get(resp, "id").String()
	if id == "" {
		t.Fatalf("expected non-empty id in response, got: %s", resp)
	}
	gotName := gjson.Get(resp, "name").String()
	if gotName != name {
		t.Errorf("expected name %q, got %q", name, gotName)
	}
	isRoleAnywhere := gjson.Get(resp, "is_role_anywhere").Bool()
	if !isRoleAnywhere {
		t.Errorf("expected is_role_anywhere=true in response, got: %s", resp)
	}

	fmt.Printf("✔ TestLive_CreateAWSConnectionIAMAnywhere: created connection id=%s name=%s\n", id, gotName)
	t.Logf("Connection created and left on server: id=%s name=%s", id, gotName)
}
