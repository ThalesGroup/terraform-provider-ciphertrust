package provider

import (
	"context"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func cmKeyConfig(name, description string) string {
	return providerConfig + `
resource "ciphertrust_cm_key" "test_key" {
  name        = "` + name + `"
  algorithm   = "aes"
  key_size    = 256
  usage_mask  = 12
  undeletable = false
  unexportable = false
  description = "` + description + `"
}
`
}

func cmKeyMaterialConfig(name, material string) string {
	return providerConfig + `
resource "ciphertrust_cm_key" "test_key" {
  name      = "` + name + `"
  algorithm = "aes"
  key_size  = 128
  material  = "` + material + `"
  usage_mask = 12
}
`
}

func TestAccCMKey_driftDetection(t *testing.T) {
	RequireCM(t)
	var capturedID string
	keyName := "tfacc-key-drift-" + uuid.NewString()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyConfig(keyName, "initial-desc"),
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "description", "initial-desc"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_cm_key.test_key"]
						if !ok {
							return nil
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				Config:             cmKeyConfig(keyName, "initial-desc"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_KEY_MANAGEMENT,
						[]byte(`{"description":"oob-changed"}`),
						"id",
					)
				},
				Config:             cmKeyConfig(keyName, "initial-desc"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCMKey_readWriteOnlyFieldsStable(t *testing.T) {
	RequireCM(t)
	keyName := "tfacc-key-wofs-" + uuid.NewString()[:8]
	// Import a key with explicit material; Read() must not clear material from state.
	material := "00112233445566778899aabbccddeeff"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyMaterialConfig(keyName, material),
				Check: checkStep(t, "write-only stable: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "material", material),
				),
			},
			{
				Config:             cmKeyMaterialConfig(keyName, material),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMKey_readRemovesStateOn404(t *testing.T) {
	RequireCM(t)
	var capturedID string
	keyName := "tfacc-key-404-" + uuid.NewString()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmKeyConfig(keyName, "404-test"),
				Check: checkStep(t, "404: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_cm_key.test_key"]
						if !ok {
							return nil
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				Config:             cmKeyConfig(keyName, "404-test"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_KEY_MANAGEMENT+"/"+capturedID,
					)
				},
				Config:             cmKeyConfig(keyName, "404-test"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

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
  name="terraform"
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
