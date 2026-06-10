package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

// TestAccCMKey_driftDetection verifies that Read() surfaces an out-of-band
// change to a key's description as a non-empty plan diff.
func TestAccCMKey_driftDetection(t *testing.T) {
	var capturedKeyID string
	const resourceName = "ciphertrust_cm_key.drift_key"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "drift_key" {
  name        = "terraform-drift-test"
  algorithm   = "aes"
  key_size    = 256
  usage_mask  = 76
  description = "initial"
}
`,
				Check: checkStep(t, "Create",
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "description", "initial"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource not found: %s", resourceName)
						}
						capturedKeyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload, _ := json.Marshal(map[string]string{"description": "oob-updated"})
					_, _ = client.UpdateData(context.Background(), capturedKeyID, common.URL_KEY_MANAGEMENT, payload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "Drift Detected",
					resource.TestCheckResourceAttr(resourceName, "description", "oob-updated"),
				),
			},
		},
	})
}

// TestAccCMKey_noSpuriousDrift verifies that write-only fields (material)
// preserved from prior state do not produce phantom diffs on subsequent plans.
func TestAccCMKey_noSpuriousDrift(t *testing.T) {
	const resourceName = "ciphertrust_cm_key.nodrift_key"
	const cfg = providerConfig + `
resource "ciphertrust_cm_key" "nodrift_key" {
  name       = "terraform-nodrift-test"
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 76
  material   = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Create with material",
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
				Check: checkStep(t, "No spurious drift on write-only field",
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
		},
	})
}
