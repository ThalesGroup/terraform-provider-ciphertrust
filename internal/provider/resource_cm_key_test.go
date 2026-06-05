package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

// TestAccCipherTrustCMKey_RevocationFieldsRoundtrip verifies revocation fields
// reach CM unswapped (TFIN-286).
func TestAccCipherTrustCMKey_RevocationFieldsRoundtrip(t *testing.T) {
	const resourceName = "ciphertrust_cm_key.revocation_key"
	const wantReason = "Unspecified"
	const wantMessage = "decommissioned-by-acceptance-test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "revocation_key" {
  name              = "terraform-tfin286-revocation"
  algorithm         = "aes"
  key_size          = 256
  usage_mask        = 76
  revocation_reason  = %q
  revocation_message = %q
}
`, wantReason, wantMessage),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "revocation_reason", wantReason),
					resource.TestCheckResourceAttr(resourceName, "revocation_message", wantMessage),
					testAccCheckCMKeyRevocationOnServer(resourceName, wantReason, wantMessage),
				),
			},
		},
	})
}

// testAccCheckCMKeyRevocationOnServer fetches the key from CM and asserts the
// server-side revocationReason/revocationMessage are not swapped.
func testAccCheckCMKeyRevocationOnServer(resourceName, wantReason, wantMessage string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		keyID := rs.Primary.ID
		if keyID == "" {
			return fmt.Errorf("resource %s has no ID set", resourceName)
		}

		client, ok := createCMClient()
		if !ok {
			return fmt.Errorf("failed to create CM client for server-side revocation check")
		}

		resp, err := client.GetById(context.Background(), "tfin286-revocation-check", keyID, common.URL_KEY_MANAGEMENT)
		if err != nil {
			return fmt.Errorf("failed to fetch key %s from CM: %w", keyID, err)
		}

		if gotReason := gjson.Get(resp, "revocationReason").String(); gotReason != wantReason {
			return fmt.Errorf("server-side revocationReason = %q, want %q (tags may be swapped): %s", gotReason, wantReason, resp)
		}
		if gotMessage := gjson.Get(resp, "revocationMessage").String(); gotMessage != wantMessage {
			return fmt.Errorf("server-side revocationMessage = %q, want %q (tags may be swapped): %s", gotMessage, wantMessage, resp)
		}
		return nil
	}
}
