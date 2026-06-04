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

// TestAccCipherTrustCMKey_readDriftRecreate verifies the cm_key Read()
// implementation added in TFIN-293. Previously Read() was empty, so an
// out-of-band deletion of the key on CipherTrust Manager was invisible to
// Terraform and `plan` reported "no changes". With a real Read():
//
//	Step 1 - create the key and capture its id.
//	Step 2 - delete the key out-of-band via the CM client in PreConfig, then
//	         refresh. Read() must detect the 404, remove the key from state and
//	         produce a non-empty plan (ExpectNonEmptyPlan).
//	Step 3 - re-apply the same config to recreate the key.
//
// The test needs a live CipherTrust Manager (provided via CIPHERTRUST_ADDRESS /
// USERNAME / PASSWORD); it is skipped when those are not set.
func TestAccCipherTrustCMKey_readDriftRecreate(t *testing.T) {
	if _, ok := createCMClient(); !ok {
		t.Skip("CIPHERTRUST_ADDRESS/USERNAME/PASSWORD not set; skipping live drift test")
	}

	keyName := "tf-drift-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_cm_key.drift_key"
	keyConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "drift_key" {
  name       = "%s"
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 76
}
`, keyName)

	var capturedKeyID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key and capture its id for the out-of-band delete.
				Config: keyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("key resource not found in state")
						}
						capturedKeyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: delete the key out-of-band, then refresh. Read() detects
				// the 404 and drops the key from state, yielding a non-empty plan.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"cm-key-drift-test",
						common.URL_KEY_MANAGEMENT+"/"+capturedKeyID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: re-apply the same config to recreate the key.
				Config: keyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
				),
			},
		},
	})
}
