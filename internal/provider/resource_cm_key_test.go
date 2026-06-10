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
// are serialised under their correct JSON keys (revocationReason / revocationMessage).
//
// Read() is a no-op on this resource, so a plan-only check is not sufficient to confirm
// correct CM-side values — state is always written from plan regardless of what CM stores.
// The primary verification uses createCMClient + GetById to read the key directly from CM
// and assert that both fields are stored correctly on the CM side.
func TestAccCMKey_RevocationFields(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping acceptance test")
	}

	const resourceName = "ciphertrust_cm_key.revoc_key"
	const wantReason = "KeyCompromise"
	const wantMessage = "test-revocation-message"

	createConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "revoc_key" {
  name                = "tf-acc-revoc-key"
  algorithm           = "aes"
  key_size            = 256
  usage_mask          = 76
  undeletable         = false
  unexportable        = false
  revocation_reason   = %q
  revocation_message  = %q
}
`, wantReason, wantMessage)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "revocation_reason", wantReason),
					resource.TestCheckResourceAttr(resourceName, "revocation_message", wantMessage),
					// Out-of-band CM verification: Read() is a no-op so we must query CM
					// directly to confirm the JSON tags were serialised correctly.
					func(s *terraform.State) error {
						keyID, err := getResourceAttr(resourceName, "id")(s)
						if err != nil {
							return fmt.Errorf("could not get key id from state: %w", err)
						}
						client, ok := createCMClient()
						if !ok {
							return fmt.Errorf("could not create CM client for out-of-band verification")
						}
						resp, err := client.GetById(context.Background(), uuid.NewString(), keyID, common.URL_KEY_MANAGEMENT)
						if err != nil {
							return fmt.Errorf("GetById failed for key %s: %w", keyID, err)
						}
						gotReason := gjson.Get(resp, "revocationReason").String()
						gotMessage := gjson.Get(resp, "revocationMessage").String()
						if gotReason != wantReason {
							return fmt.Errorf("CM revocationReason = %q, want %q (tags may still be swapped)", gotReason, wantReason)
						}
						if gotMessage != wantMessage {
							return fmt.Errorf("CM revocationMessage = %q, want %q (tags may still be swapped)", gotMessage, wantMessage)
						}
						return nil
					},
				),
			},
			// Confirm no perpetual diff after create.
			// Note: because Read() is a no-op, this step passes regardless of CM-side
			// state; the step above is the authoritative serialisation check.
			{
				Config:             createConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
