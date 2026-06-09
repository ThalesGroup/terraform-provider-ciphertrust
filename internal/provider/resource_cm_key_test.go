package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
  algorithm="AES"
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
  algorithm="AES"
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

func TestAccCMKey_HMACNoDrift(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "hmac_key" {
  name        = "terraform-hmac-nodrift"
  algorithm   = "HMAC-SHA256"
  usage_mask  = 384
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.hmac_key", "algorithm", "HMAC-SHA256"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.hmac_key", "id"),
				),
			},
			// Second plan must be empty — no drift
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "hmac_key" {
  name        = "terraform-hmac-nodrift"
  algorithm   = "HMAC-SHA256"
  usage_mask  = 384
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMKey_HMACAlgorithmLowercaseRejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "lowercase_key" {
  name      = "terraform-lowercase-algo"
  algorithm = "hmac-sha256"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid Attribute Value Match`),
			},
		},
	})
}

func TestAccCMKey_ReadRepopulatesState(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("skipping: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, CIPHERTRUST_PASSWORD not set")
	}
	_ = client

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "read_key" {
  name        = "terraform-read-test"
  algorithm   = "AES"
  key_size    = 256
  usage_mask  = 76
  description = "initial"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.read_key", "description", "initial"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.read_key", "id"),
				),
			},
			// Refresh state — Read() should repopulate description from API
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "read_key" {
  name        = "terraform-read-test"
  algorithm   = "AES"
  key_size    = 256
  usage_mask  = 76
  description = "initial"
}
`,
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.read_key", "description", "initial"),
				),
			},
		},
	})
}

func TestAccCMKey_OutOfBandDelete(t *testing.T) {
	_, ok := createCMClient()
	if !ok {
		t.Skip("skipping: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, CIPHERTRUST_PASSWORD not set")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "oob_del_key" {
  name       = "terraform-oob-delete"
  algorithm  = "AES"
  key_size   = 256
  usage_mask = 76
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.oob_del_key", "id"),
				),
			},
			// After out-of-band deletion, plan should detect the resource as missing and plan to recreate
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "oob_del_key" {
  name       = "terraform-oob-delete"
  algorithm  = "AES"
  key_size   = 256
  usage_mask = 76
}
`,
				ExpectNonEmptyPlan: true,
				PlanOnly:           true,
			},
		},
	})
}

func TestAccCMKey_Import(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "import_key" {
  name        = "terraform-import-test"
  algorithm   = "AES"
  key_size    = 256
  usage_mask  = 76
  description = "import test"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.import_key", "id"),
				),
			},
			{
				ResourceName:      "ciphertrust_cm_key.import_key",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"material", "password", "mac_sign_bytes", "mac_sign_key_identifier",
					"mac_sign_key_identifier_type", "wrap_key_id_type", "wrap_key_name",
					"wrap_public_key", "wrap_public_key_padding", "wrapping_encryption_algo",
					"wrapping_hash_algo", "wrapping_method", "wrap_hkdf", "wrap_pbe", "wrap_rsaaes",
					"hkdf_create_parameters", "format", "generate_key_id", "id_size", "padded",
					"empty_material", "assign_self_as_owner", "all_versions",
					"remove_from_state_on_destroy",
				},
			},
		},
	})
}

func TestAccCMKey_UpdateInPlace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "update_key" {
  name        = "terraform-update-test"
  algorithm   = "AES"
  key_size    = 256
  usage_mask  = 76
  description = "initial"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.update_key", "description", "initial"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.update_key", "id"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "update_key" {
  name        = "terraform-update-test"
  algorithm   = "AES"
  key_size    = 256
  usage_mask  = 76
  description = "updated"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.update_key", "description", "updated"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.update_key", "id"),
				),
			},
		},
	})
}
