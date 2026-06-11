package provider

import (
	"context"
	"encoding/json"
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

// TestAccCMKey_driftDetection verifies that Read() surfaces OOB changes and
// that a key deleted OOB causes RemoveResource so Terraform plans to recreate it.
func TestAccCMKey_driftDetection(t *testing.T) {
	cmClient, ok := createCMClient()
	if !ok {
		t.Skip("CM client not configured")
	}

	keyName := "tf-drift-" + uuid.NewString()[:8]
	keyConfig := fmt.Sprintf(providerConfig+`
resource "ciphertrust_cm_key" "test" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  usage_mask  = 76
  description = "original"
}
`, keyName)

	var keyID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create and capture ID only — no OOB change here so the
			// framework's automatic post-step empty-plan check can pass.
			{
				Config: keyConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "description", "original"),
					func(s *terraform.State) error {
						var err error
						keyID, err = getResourceAttr("ciphertrust_cm_key.test", "id")(s)
						return err
					},
				),
			},
			// Step 2: Mutate description OOB via PreConfig; plan must detect drift.
			{
				Config:             keyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"description": "changed-oob"})
					ctx := context.Background()
					_, _ = cmClient.UpdateData(ctx, keyID, common.URL_KEY_MANAGEMENT, patchPayload, "id")
				},
			},
			// Step 3: Apply original config; assert stable state.
			{
				Config: keyConfig,
				Check: checkStep(t, "reconcile",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "description", "original"),
				),
			},
			// Step 4: Assert no drift on a fresh plan.
			{
				Config:             keyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 5: Delete key OOB; plan should show resource as to-be-created.
			{
				Config:             keyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				PreConfig: func() {
					ctx := context.Background()
					_, _ = cmClient.DeleteByURL(ctx, uuid.NewString(), common.URL_KEY_MANAGEMENT+"/"+keyID)
				},
			},
		},
	})
}

// TestAccCMKey_readHydratesState verifies that Read() populates readable attributes
// into state and leaves unconfigured optional fields absent.
func TestAccCMKey_readHydratesState(t *testing.T) {
	keyName := "tf-hydrate-" + uuid.NewString()[:8]
	keyConfig := fmt.Sprintf(providerConfig+`
resource "ciphertrust_cm_key" "test" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  usage_mask  = 76
  undeletable = true
  object_type = "Symmetric Key"
  description = "hydrate-test"
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create.
			{
				Config: keyConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
				),
			},
			// Step 2: Refresh and assert hydrated attributes.
			{
				RefreshState: true,
				Check: checkStep(t, "refresh hydrates state",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "description", "hydrate-test"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "usage_mask", "76"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "undeletable", "true"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "object_type", "Symmetric Key"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "state"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.test", "activation_date"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.test", "key_id"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.test", "cert_type"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.test", "xts"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.test", "id_size"),
				),
			},
			// Step 3: No drift on subsequent plan.
			{
				Config:             keyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCMKey_writeOnlyPreserved verifies that Read() does not overwrite
// write-only fields (material, encoding) with null after a refresh.
func TestAccCMKey_writeOnlyPreserved(t *testing.T) {
	const material = "00112233445566778899aabbccddeeff"
	keyName := "tf-wo-" + uuid.NewString()[:8]
	keyConfig := fmt.Sprintf(providerConfig+`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "aes"
  key_size  = 128
  material  = %q
  encoding  = "hex"
}
`, keyName, material)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with material and encoding.
			{
				Config: keyConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "material", material),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "encoding", "hex"),
				),
			},
			// Step 2: Refresh; write-only fields must be preserved unchanged.
			{
				RefreshState: true,
				Check: checkStep(t, "refresh preserves write-only fields",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "material", material),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "encoding", "hex"),
				),
			},
			// Step 3: No drift on subsequent plan.
			{
				Config:             keyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
