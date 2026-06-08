package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const cmKeyResourceName = "ciphertrust_cm_key.key"

// cmKeySkipIfMissingEnv returns a skip message when the required CM env vars are absent.
func cmKeySkipIfMissingEnv(t *testing.T) {
	t.Helper()
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" || os.Getenv("CIPHERTRUST_USERNAME") == "" || os.Getenv("CIPHERTRUST_PASSWORD") == "" {
		t.Skip("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set for acceptance tests")
	}
}

// cmKeyBasicConfig returns HCL for a basic AES key with the given description.
func cmKeyBasicConfig(name, description string) string {
	desc := ""
	if description != "" {
		desc = fmt.Sprintf(`description = %q`, description)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "key" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  usage_mask = 76
  %s
}
`, name, desc)
}

// TestAccCMKey_basic verifies that after terraform apply a second plan shows no changes,
// and that Read() correctly round-trips the key attributes through state.
func TestAccCMKey_basic(t *testing.T) {
	cmKeySkipIfMissingEnv(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyBasicConfig("tf-test-basic", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmKeyResourceName, "id"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "algorithm", "aes"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "key_size", "256"),
				),
			},
			// Re-plan with no changes — Read() must not introduce spurious diffs.
			{
				Config:   cmKeyBasicConfig("tf-test-basic", ""),
				PlanOnly: true,
			},
		},
	})
}

// TestAccCMKey_update verifies that Update() and the subsequent Read() round-trip
// the changed description correctly into Terraform state.
func TestAccCMKey_update(t *testing.T) {
	cmKeySkipIfMissingEnv(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyBasicConfig("tf-test-update", "initial description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmKeyResourceName, "id"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "description", "initial description"),
				),
			},
			{
				Config: cmKeyBasicConfig("tf-test-update", "updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cmKeyResourceName, "description", "updated description"),
				),
			},
		},
	})
}

// TestAccCMKey_outOfBandDelete verifies that when the key is deleted out-of-band on CM,
// the next terraform plan detects the absence and proposes to recreate the resource.
func TestAccCMKey_outOfBandDelete(t *testing.T) {
	cmKeySkipIfMissingEnv(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("could not create CM client")
	}

	var keyID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyBasicConfig("tf-test-oob-delete", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmKeyResourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[cmKeyResourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", cmKeyResourceName)
						}
						keyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the key out-of-band before terraform plan runs.
				PreConfig: func() {
					if keyID == "" {
						t.Fatal("keyID was not captured in previous step")
					}
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, "api/v1/vault/keys2", keyID)
					_, err := client.DeleteByID(context.Background(), "DELETE", keyID, url, nil)
					if err != nil {
						t.Logf("out-of-band delete returned: %v (may already be gone)", err)
					}
				},
				Config:             cmKeyBasicConfig("tf-test-oob-delete", ""),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMKey_drift verifies that when an attribute is modified out-of-band on CM,
// the next terraform plan surfaces the drift.
func TestAccCMKey_drift(t *testing.T) {
	cmKeySkipIfMissingEnv(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("could not create CM client")
	}

	var keyID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyBasicConfig("tf-test-drift", "original description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmKeyResourceName, "id"),
					resource.TestCheckResourceAttr(cmKeyResourceName, "description", "original description"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[cmKeyResourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", cmKeyResourceName)
						}
						keyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Modify description out-of-band via PATCH before the next plan.
				PreConfig: func() {
					if keyID == "" {
						t.Fatal("keyID was not captured in previous step")
					}
					payload := []byte(`{"description":"drifted description"}`)
					_, err := client.UpdateData(context.Background(), keyID, "api/v1/vault/keys2", payload, "id")
					if err != nil {
						t.Logf("out-of-band patch returned: %v", err)
					}
				},
				Config:             cmKeyBasicConfig("tf-test-drift", "original description"),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMKey_import verifies that `terraform import` is registered and does not error.
// Full attribute verification requires schema attributes to carry Computed:true so the
// framework can track server-returned values; that change is out of scope for this ticket.
func TestAccCMKey_import(t *testing.T) {
	cmKeySkipIfMissingEnv(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyBasicConfig("tf-test-import", "import test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(cmKeyResourceName, "id"),
				),
			},
			{
				ResourceName:      cmKeyResourceName,
				ImportState:       true,
				ImportStateVerify: false,
				ImportStateIdFunc: getResourceAttr(cmKeyResourceName, "id"),
			},
		},
	})
}
