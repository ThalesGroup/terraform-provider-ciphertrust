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

// TestAccCipherTrustCMKey_outOfBandDelete verifies that after a ciphertrust_cm_key
// is deleted out-of-band on CipherTrust Manager, a refresh detects the deletion
// and the next plan proposes recreation (TFIN-293).
func TestAccCipherTrustCMKey_outOfBandDelete(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping out-of-band test")
	}

	keyResource := "ciphertrust_cm_key.oob_key"
	keyName := "tf-oob-del-" + uuid.New().String()[:8]
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "oob_key" {
  name       = "%s"
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 76
}
`, keyName)

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key and capture its id for out-of-band deletion.
				Config: config,
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
				// Step 2: delete the key out-of-band, then refresh. Read() must detect
				// the 404, drop the key from state, and the resulting plan must be
				// non-empty (key is in config but gone from state -> recreate).
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"cm-key-oob-delete-test",
						common.URL_KEY_MANAGEMENT+"/"+capturedID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: re-apply to recover the key.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
				),
			},
		},
	})
}

// TestAccCipherTrustCMKey_outOfBandDrift verifies that an out-of-band label change
// on CipherTrust Manager is detected on refresh: Read() hydrates the drifted
// labels into state (surfacing a non-empty plan against config) while the
// server-authoritative identity fields are preserved (TFIN-293).
func TestAccCipherTrustCMKey_outOfBandDrift(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping out-of-band test")
	}

	keyResource := "ciphertrust_cm_key.drift_key"
	keyName := "tf-oob-drift-" + uuid.New().String()[:8]
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "drift_key" {
  name       = "%s"
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 76
  labels = {
    env = "test"
  }
}
`, keyName)

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key with labels and capture its id.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "labels.env", "test"),
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
				// Step 2: mutate the label out-of-band, then refresh. The refreshed
				// state must reflect the drifted label while name is preserved, and
				// the plan against config must be non-empty.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_KEY_MANAGEMENT,
						[]byte(`{"labels":{"env":"drifted"}}`),
						"id",
					)
				},
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "labels.env", "drifted"),
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
