package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// createTestLocalCA creates a new local CA on CM and self-signs it so it becomes active.
// Returns the local CA ID and a cleanup func to delete it.
// The new local CA is not yet paired with any service, so any valid service can be used.
func createTestLocalCA(t *testing.T) (caID string, cleanup func()) {
	t.Helper()
	client, ok := createCMClient()
	if !ok {
		t.Skip("CM client unavailable")
	}
	ctx := context.Background()

	body, err := json.Marshal(map[string]interface{}{
		"cn": "TF-Test-CA-" + uuid.New().String()[:8],
	})
	if err != nil {
		t.Skipf("Cannot marshal local CA body: %v", err)
	}
	resp, err2 := client.PostDataV2(ctx, uuid.New().String(), common.URL_LOCAL_CA, body)
	if err2 != nil {
		t.Skipf("Cannot create test local CA: %v", err2)
	}
	caID = gjson.Get(resp, "id").String()
	if caID == "" {
		t.Skip("Local CA creation returned no ID")
	}

	// Self-sign to move the CA from "pending" to "active" state.
	selfSignEndpoint := fmt.Sprintf("%s/%s/self-sign", common.URL_LOCAL_CA, caID)
	selfSignBody, _ := json.Marshal(map[string]interface{}{"duration": 3650})
	_, err3 := client.PostDataV2(ctx, uuid.New().String(), selfSignEndpoint, selfSignBody)
	if err3 != nil {
		// Clean up the pending CA and skip.
		delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_LOCAL_CA, caID)
		_, _ = client.DeleteByID(ctx, "DELETE", caID, delURL, nil)
		t.Skipf("Cannot self-sign test local CA: %v", err3)
	}

	cleanup = func() {
		delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_LOCAL_CA, caID)
		_, _ = client.DeleteByID(ctx, "DELETE", caID, delURL, nil)
	}
	return caID, cleanup
}

// discoverValidService returns the first service name found in existing trusted CA entries.
// Skips the test if no service names can be determined.
func discoverValidService(t *testing.T) string {
	t.Helper()
	client, ok := createCMClient()
	if !ok {
		t.Skip("CM client unavailable — cannot discover service names")
	}
	resp, err := client.GetAll(context.Background(), uuid.New().String(), common.URL_TRUSTED_CAS)
	if err != nil {
		t.Skipf("Cannot list trusted CAs to discover service names: %v", err)
	}
	for _, entry := range gjson.Parse(resp).Array() {
		svc := entry.Get("service").String()
		if svc != "" {
			return svc
		}
	}
	t.Skip("No existing trusted CA entries found — cannot determine valid service name for this CM")
	return "" // unreachable
}

// Test_CM_TrustedCAs_Basic creates a single trusted CA entry and asserts idempotency.
// Uses a freshly created external CA to avoid conflicts with existing entries.
func Test_CM_TrustedCAs_Basic(t *testing.T) {
	RequireCM(t)

	// Create a temporary external CA to use as our test CA.
	caID, cleanupCA := createTestLocalCA(t)
	defer cleanupCA()

	// Discover a valid service name from existing entries.
	service := discoverValidService(t)

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = %q
}
`, caID, service)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create and verify the trusted CA entry.
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_trusted_cas.test", "ca_id", caID),
					resource.TestCheckResourceAttr("ciphertrust_trusted_cas.test", "service", service),
				),
			},
			// Step 2: Verify no drift on a subsequent plan.
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_TrustedCAs_Bulk creates a trusted CA entry via the bulk endpoint and asserts idempotency.
func Test_CM_TrustedCAs_Bulk(t *testing.T) {
	RequireCM(t)

	caID, cleanupCA := createTestLocalCA(t)
	defer cleanupCA()

	service := discoverValidService(t)

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id    = %q
  service  = %q
  use_bulk = true
}
`, caID, service)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create via bulk endpoint and verify non-empty ID.
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_trusted_cas.test", "ca_id", caID),
					resource.TestCheckResourceAttr("ciphertrust_trusted_cas.test", "service", service),
					resource.TestCheckResourceAttr("ciphertrust_trusted_cas.test", "use_bulk", "true"),
				),
			},
			// Step 2: Verify no drift on a subsequent plan.
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_TrustedCAs_OOBDelete verifies that Read() handles a 404 gracefully by removing
// the resource from state, surfacing a non-empty plan on the next refresh.
func Test_CM_TrustedCAs_OOBDelete(t *testing.T) {
	RequireCM(t)

	caID, cleanupCA := createTestLocalCA(t)
	defer cleanupCA()

	service := discoverValidService(t)

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = %q
}
`, caID, service)

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create and capture the resource ID.
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_trusted_cas.test"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: Delete out-of-band, then refresh — Read() returns 404 and removes
			// the resource from state, so the plan shows it as needing recreation.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB delete step")
						return
					}
					delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_TRUSTED_CAS, capturedID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", capturedID, delURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_TrustedCAs_ImmutableField verifies that changing an immutable field (service) is
// rejected at plan time with no API call made.
func Test_CM_TrustedCAs_ImmutableField(t *testing.T) {
	RequireCM(t)

	caID, cleanupCA := createTestLocalCA(t)
	defer cleanupCA()

	service := discoverValidService(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with the discovered service value.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = %q
}
`, caID, service),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "id"),
			},
			// Step 2: Attempt to change service — immutable modifier must reject it at plan time.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "kmip-changed-service"
}
`, caID),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)attribute is immutable`),
			},
		},
	})
}
