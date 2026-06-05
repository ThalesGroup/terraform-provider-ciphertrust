package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const cmKeyResourceName = "ciphertrust_cm_key.test_key"

// cmKeyConfig returns an HCL configuration for a minimal AES ciphertrust_cm_key
// with the supplied name and a body of additional attributes (which must include
// usage_mask). usage_mask is deliberately not part of the fixed template so that
// tests can vary it without producing a duplicate-attribute error.
func cmKeyConfig(name string, body string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name       = "%s"
  algorithm  = "aes"
  key_size   = 256
%s
}
`, name, body)
}

// captureCMKeyID returns a TestCheckFunc that records the primary ID of the
// ciphertrust_cm_key resource into the supplied pointer so a later PreConfig can
// mutate it out-of-band.
func captureCMKeyID(id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[cmKeyResourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", cmKeyResourceName)
		}
		*id = rs.Primary.ID
		return nil
	}
}

// TestAccResourceCMKey_basic creates a minimal AES key and asserts the
// configured, readable attributes are populated into state.
func TestAccResourceCMKey_basic(t *testing.T) {
	keyName := "tf-acc-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyConfig(keyName, "  usage_mask = 76"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmKeyResourceName, "id"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "name", keyName),
					resource.TestCheckResourceAttr(cmKeyResourceName, "algorithm", "aes"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "key_size", "256"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "usage_mask", "76"),
				),
			},
		},
	})
}

// TestAccResourceCMKey_update changes description, usage_mask and labels and
// asserts the post-update GET driven state reflects the new values.
func TestAccResourceCMKey_update(t *testing.T) {
	keyName := "tf-acc-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyConfig(keyName, "  usage_mask  = 12\n  description = \"initial\""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cmKeyResourceName, "description", "initial"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "usage_mask", "12"),
				),
			},
			{
				Config: cmKeyConfig(keyName, "  usage_mask  = 13\n  description = \"updated\"\n  labels = {\n    env = \"test\"\n  }"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cmKeyResourceName, "description", "updated"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "usage_mask", "13"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "labels.env", "test"),
				),
			},
		},
	})
}

// TestAccResourceCMKey_outOfBandDelete deletes the key directly on CipherTrust
// Manager and asserts that Read detects the 404, removes the resource from
// state, and the next plan is non-empty (proposing a recreate).
func TestAccResourceCMKey_outOfBandDelete(t *testing.T) {
	keyName := "tf-acc-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyConfig(keyName, "  usage_mask = 76"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmKeyResourceName, "id"),
					captureCMKeyID(&capturedID),
				),
			},
			{
				// Delete the key out-of-band, then refresh: Read must 404 and
				// remove it from state, leaving a non-empty plan.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(context.Background(), "tfin292-oob-delete", common.URL_KEY_MANAGEMENT+"/"+capturedID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccResourceCMKey_attributeDrift mutates readable attributes directly on
// CipherTrust Manager and asserts that Read detects the drift on the configured
// attributes, leaving a non-empty plan.
func TestAccResourceCMKey_attributeDrift(t *testing.T) {
	keyName := "tf-acc-" + uuid.New().String()[:8]
	var capturedID string
	config := cmKeyConfig(keyName, "  usage_mask = 76\n  description = \"before\"\n  labels = {\n    owner = \"team-a\"\n  }")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(cmKeyResourceName, "description", "before"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "labels.owner", "team-a"),
					captureCMKeyID(&capturedID),
				),
			},
			{
				// Mutate description and labels out-of-band, then refresh: Read
				// must overwrite the in-state values with the CM values, leaving a
				// non-empty plan that proposes restoring the configured values.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patch := []byte(`{"description":"after-oob","labels":{"owner":"team-b"}}`)
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, patch, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
