package provider

import (
	"fmt"
	"testing"

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

// cmKeyRevocationConfig returns a Terraform config that creates a ciphertrust_cm_key
// with the given revocation_reason and revocation_message, plus a
// ciphertrust_cm_keys_list data source filtered by the key name.
func cmKeyRevocationConfig(keyName, reason, message string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "revoc_key" {
  name              = %q
  algorithm         = "aes"
  key_size          = 256
  usage_mask        = 76
  revocation_reason = %q
  revocation_message = %q
}

data "ciphertrust_cm_keys_list" "revoc_list" {
  depends_on = [ciphertrust_cm_key.revoc_key]
  filters = {
    name = %q
  }
}
`, keyName, reason, message, keyName)
}

// checkCMKeyRevocationReason returns a TestCheckFunc that verifies the first
// matching key in the ciphertrust_cm_keys_list data source has the expected
// revocation_reason stored in CM (i.e. the CM API received the correct field).
func checkCMKeyRevocationReason(expectedReason string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources["data.ciphertrust_cm_keys_list.revoc_list"]
		if !ok {
			return fmt.Errorf("data source ciphertrust_cm_keys_list.revoc_list not found in state")
		}
		countStr, ok := rs.Primary.Attributes["keys.#"]
		if !ok {
			return fmt.Errorf("keys.# not found in data source state")
		}
		count := 0
		fmt.Sscanf(countStr, "%d", &count)
		if count == 0 {
			return fmt.Errorf("expected at least one key in ciphertrust_cm_keys_list but got 0")
		}
		actual := rs.Primary.Attributes["keys.0.revocation_reason"]
		if actual != expectedReason {
			return fmt.Errorf("revocation_reason: got %q, want %q (fields may be transposed)", actual, expectedReason)
		}
		return nil
	}
}

// TestAccCMKey_RevocationFieldsCorrect verifies that revocation_reason and
// revocation_message are serialised to the correct CM API fields after the
// struct-tag fix (TFIN-286). The data source asserts the CM-stored
// revocationReason equals the configured value, not the message value.
func TestAccCMKey_RevocationFieldsCorrect(t *testing.T) {
	keyName := "tfin286-revoc-correct"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyRevocationConfig(keyName, "Superseded", "test-message"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.revoc_key", "id"),
					// Verify the resource state carries the configured values.
					resource.TestCheckResourceAttr("ciphertrust_cm_key.revoc_key", "revocation_reason", "Superseded"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.revoc_key", "revocation_message", "test-message"),
					// Verify CM stored revocationReason = "Superseded", not "test-message".
					checkCMKeyRevocationReason("Superseded"),
				),
			},
			// Confirm no perpetual drift on a subsequent plan.
			{
				Config:             cmKeyRevocationConfig(keyName, "Superseded", "test-message"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCMKey_RevocationFieldsDistinct verifies the fix with a second valid
// revocation reason enum value to confirm neither field is transposed.
func TestAccCMKey_RevocationFieldsDistinct(t *testing.T) {
	keyName := "tfin286-revoc-distinct"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyRevocationConfig(keyName, "KeyCompromise", "reason-msg"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.revoc_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.revoc_key", "revocation_reason", "KeyCompromise"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.revoc_key", "revocation_message", "reason-msg"),
					// Verify CM stored revocationReason = "KeyCompromise", not "reason-msg".
					checkCMKeyRevocationReason("KeyCompromise"),
				),
			},
			// Confirm no perpetual drift on a subsequent plan.
			{
				Config:             cmKeyRevocationConfig(keyName, "KeyCompromise", "reason-msg"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
