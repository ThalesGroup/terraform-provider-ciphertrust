package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
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

// TestAccCMKey_RevocationFields verifies that revocation_reason and revocation_message
// are serialized to the correct JSON keys when creating a CM key.
// The Read() method on this resource is a no-op, so a plan-only step alone cannot
// detect swapped JSON tags. This test performs a direct CM API read via createCMClient
// + GetById to confirm the values are stored under the correct keys on CipherTrust Manager.
func TestAccCMKey_RevocationFields(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping acceptance test")
	}

	const keyResource = "ciphertrust_cm_key.revocation_test"
	const revReason = "KeyCompromise"
	const revMsg = "test-revocation-message"

	config := fmt.Sprintf(`
provider "ciphertrust" {}
resource "ciphertrust_cm_key" "revocation_test" {
  name               = "tf-revoc-%s"
  algorithm          = "aes"
  key_size           = 256
  usage_mask         = 76
  revocation_reason  = %q
  revocation_message = %q
}
`, uuid.New().String()[:8], revReason, revMsg)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "revocation_reason", revReason),
					resource.TestCheckResourceAttr(keyResource, "revocation_message", revMsg),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", keyResource)
						}
						keyID := rs.Primary.ID
						client, ok := createCMClient()
						if !ok {
							return fmt.Errorf("createCMClient failed; ensure CIPHERTRUST_* env vars are set")
						}
						ctx := context.Background()
						response, err := client.GetById(ctx, uuid.NewString(), keyID, common.URL_KEY_MANAGEMENT)
						if err != nil {
							return fmt.Errorf("GetById failed for key %s: %s", keyID, err.Error())
						}
						cmRevReason := gjson.Get(response, "revocationReason").String()
						cmRevMsg := gjson.Get(response, "revocationMessage").String()
						if cmRevReason != revReason {
							return fmt.Errorf("CM revocationReason = %q, want %q (JSON tags may be swapped)", cmRevReason, revReason)
						}
						if cmRevMsg != revMsg {
							return fmt.Errorf("CM revocationMessage = %q, want %q (JSON tags may be swapped)", cmRevMsg, revMsg)
						}
						return nil
					},
				),
			},
			{
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}
