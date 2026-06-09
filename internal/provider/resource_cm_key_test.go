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
			// Verify no drift after update
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
				PlanOnly: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccCipherTrustCMKey_HMACAlgorithmNoDrift(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "hmac_key" {
  name       = "terraform-hmac-nodrift"
  algorithm  = "HMAC-SHA256"
  usage_mask = 384
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.hmac_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.hmac_key", "algorithm", "HMAC-SHA256"),
				),
			},
			// Second plan with same config must produce empty diff (no drift)
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "hmac_key" {
  name       = "terraform-hmac-nodrift"
  algorithm  = "HMAC-SHA256"
  usage_mask = 384
}
`,
				PlanOnly: true,
			},
		},
	})
}

func TestAccCipherTrustCMKey_HMACAlgorithmValidatorRejectsLowercase(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "hmac_key" {
  name       = "terraform-hmac-lowercase"
  algorithm  = "hmac-sha256"
  usage_mask = 384
}
`,
				ExpectError: regexp.MustCompile(`value must be one of`),
			},
		},
	})
}

func TestAccCipherTrustCMKey_HMACAlgorithmVariants(t *testing.T) {
	variants := []string{
		"HMAC-SHA1",
		"HMAC-SHA224",
		"HMAC-SHA256",
		"HMAC-SHA384",
		"HMAC-SHA512",
	}
	for _, algo := range variants {
		algo := algo
		t.Run(algo, func(t *testing.T) {
			config := providerConfig + `
resource "ciphertrust_cm_key" "hmac_variant_key" {
  name       = "terraform-hmac-variant"
  algorithm  = "` + algo + `"
  usage_mask = 384
}
`
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: config,
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttrSet("ciphertrust_cm_key.hmac_variant_key", "id"),
							resource.TestCheckResourceAttr("ciphertrust_cm_key.hmac_variant_key", "algorithm", algo),
						),
					},
					// Verify no drift after apply
					{
						Config:   config,
						PlanOnly: true,
					},
				},
			})
		})
	}
}

func TestAccCipherTrustCMKey_NonHMACAlgorithmUnaffected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "aes_key" {
  name       = "terraform-aes-unaffected"
  algorithm  = "AES"
  key_size   = 256
  usage_mask = 12
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.aes_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.aes_key", "algorithm", "AES"),
				),
			},
			// Verify no drift for non-HMAC algorithm
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "aes_key" {
  name       = "terraform-aes-unaffected"
  algorithm  = "AES"
  key_size   = 256
  usage_mask = 12
}
`,
				PlanOnly: true,
			},
		},
	})
}
