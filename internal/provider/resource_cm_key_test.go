package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMKey(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_users_list" "users_list" {
  filters = {
    username = "admin"
  }
}

resource "ciphertrust_cm_key" "cte_key" {
  name="terraform"
  algorithm="aes"
  key_size=256
  usage_mask=76
  undeletable=false
  unexportable=false
  meta={
    owner_id=tolist(data.ciphertrust_cm_users_list.users_list.users)[0].user_id
    permissions={
      decrypt_with_key=["CTE Clients"]
      encrypt_with_key=["CTE Clients"]
      export_key=["CTE Clients"]
      mac_verify_with_key=["CTE Clients"]
      mac_with_key=["CTE Clients"]
      read_key=["CTE Clients"]
      sign_verify_with_key=["CTE Clients"]
      sign_with_key=["CTE Clients"]
      use_key=["CTE Clients"]
    }
    cte={
      persistent_on_client=true
      encryption_mode="CBC"
      cte_versioned=false
    }
    xts=false
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.cte_key", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "cte_key" {
  name="terraform_upd"
  algorithm="aes"
  key_size=256
  usage_mask=13
  description="updated via terraform"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.cte_key", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// cmKeyOOBConfig is a minimal generated AES key used by the out-of-band
// reconciliation tests (TFIN-293).
const cmKeyOOBConfig = `
resource "ciphertrust_cm_key" "oob_key" {
  name       = "tf-oob-cm-key"
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 76
}
`

// TestResourceCMKeyOutOfBandDelete verifies that after a key is deleted out of
// band on CipherTrust Manager, Read() drops it from state (404 ->
// RemoveResource) so the next plan proposes to recreate it (TFIN-293).
func TestResourceCMKeyOutOfBandDelete(t *testing.T) {
	const keyResource = "ciphertrust_cm_key.oob_key"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create the key and capture its ID for the out-of-band delete.
				Config: providerConfig + cmKeyOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("%s not found in state", keyResource)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the key out of band, then refresh: Read must remove it
				// from state and the plan must propose to recreate it.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"tfin293-key-oob-delete",
						common.URL_KEY_MANAGEMENT+"/"+capturedID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Recovery: re-apply to recreate the key so teardown is clean.
				Config: providerConfig + cmKeyOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
				),
			},
		},
	})
}

// TestResourceCMKeyOutOfBandDrift verifies that an out-of-band modification of a
// managed attribute (usage_mask) is surfaced as a plan diff after refresh
// (TFIN-293).
func TestResourceCMKeyOutOfBandDrift(t *testing.T) {
	const keyResource = "ciphertrust_cm_key.oob_key"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cmKeyOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "usage_mask", "76"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("%s not found in state", keyResource)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Mutate usage_mask out of band, then refresh: Read must pick up
				// the drift and the plan must be non-empty.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_KEY_MANAGEMENT,
						[]byte(`{"usageMask":12}`),
						"id",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
