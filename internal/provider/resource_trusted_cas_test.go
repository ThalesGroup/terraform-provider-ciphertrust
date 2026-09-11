package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Test_CM_TrustedCAs_SingleCreate verifies single-endpoint creation and that
// a subsequent plan shows no drift.
func Test_CM_TrustedCAs_SingleCreate(t *testing.T) {
	RequireCM(t)
	caID := os.Getenv("CIPHERTRUST_TEST_LOCAL_CA_ID")
	if caID == "" {
		t.Skip("CIPHERTRUST_TEST_LOCAL_CA_ID not set — skipping")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create and verify computed fields are populated.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "nae"
}
`, caID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "created_at"),
					resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "subject"),
				),
			},
			// Step 2: no drift on subsequent plan.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "nae"
}
`, caID),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_TrustedCAs_BulkCreate verifies the bulk-create endpoint path and
// that ca_id and service are preserved in state from plan.
func Test_CM_TrustedCAs_BulkCreate(t *testing.T) {
	RequireCM(t)
	certList := os.Getenv("CIPHERTRUST_TEST_TRUSTED_CA_CERTLIST")
	caID := os.Getenv("CIPHERTRUST_TEST_LOCAL_CA_ID")
	if certList == "" || caID == "" {
		t.Skip("CIPHERTRUST_TEST_TRUSTED_CA_CERTLIST or CIPHERTRUST_TEST_LOCAL_CA_ID not set — skipping")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: bulk create and verify id, ca_id, service are in state.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "bulk" {
  ca_id     = %q
  service   = "nae"
  cert_list = %q
}
`, caID, certList),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.bulk", "id"),
					resource.TestCheckResourceAttr("ciphertrust_trusted_cas.bulk", "ca_id", caID),
					resource.TestCheckResourceAttr("ciphertrust_trusted_cas.bulk", "service", "nae"),
				),
			},
			// Step 2: no drift on subsequent plan.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "bulk" {
  ca_id     = %q
  service   = "nae"
  cert_list = %q
}
`, caID, certList),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_TrustedCAs_ImmutableCAID verifies that changing ca_id is blocked at
// plan time by the ImmutableString modifier.
func Test_CM_TrustedCAs_ImmutableCAID(t *testing.T) {
	RequireCM(t)
	caIDA := os.Getenv("CIPHERTRUST_TEST_LOCAL_CA_ID")
	caIDB := os.Getenv("CIPHERTRUST_TEST_LOCAL_CA_ID_ALT")
	if caIDA == "" || caIDB == "" {
		t.Skip("CIPHERTRUST_TEST_LOCAL_CA_ID or CIPHERTRUST_TEST_LOCAL_CA_ID_ALT not set — skipping")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with ca_id A.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "nae"
}
`, caIDA),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "id"),
			},
			// Step 2: attempt to change ca_id — plan must fail with immutability error.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "nae"
}
`, caIDB),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_TrustedCAs_ImmutableService verifies that changing service is blocked
// at plan time by the ImmutableString modifier.
func Test_CM_TrustedCAs_ImmutableService(t *testing.T) {
	RequireCM(t)
	caID := os.Getenv("CIPHERTRUST_TEST_LOCAL_CA_ID")
	if caID == "" {
		t.Skip("CIPHERTRUST_TEST_LOCAL_CA_ID not set — skipping")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with service "nae".
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "nae"
}
`, caID),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_trusted_cas.test", "id"),
			},
			// Step 2: attempt to change service — plan must fail with immutability error.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "web"
}
`, caID),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_TrustedCAs_OOBDelete verifies that when a trusted CA is deleted
// out-of-band, terraform destroy succeeds with a warning (404 guard in Delete).
// Read() is a no-op, so RefreshState does not detect the deletion; the 404
// guard is exercised during post-test destroy cleanup.
func Test_CM_TrustedCAs_OOBDelete(t *testing.T) {
	RequireCM(t)
	caID := os.Getenv("CIPHERTRUST_TEST_LOCAL_CA_ID")
	if caID == "" {
		t.Skip("CIPHERTRUST_TEST_LOCAL_CA_ID not set — skipping")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create and capture the ID for OOB deletion.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_trusted_cas" "test" {
  ca_id   = %q
  service = "nae"
}
`, caID),
				Check: func(s *terraform.State) error {
					capturedID = s.RootModule().Resources["ciphertrust_trusted_cas.test"].Primary.ID
					return nil
				},
			},
			// Step 2: delete out-of-band, then refresh. Read is a no-op so no error is
			// produced; post-test destroy exercises the 404 warning guard in Delete().
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB deletion step")
						return
					}
					delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_TRUSTED_CAS, capturedID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", capturedID, delURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
