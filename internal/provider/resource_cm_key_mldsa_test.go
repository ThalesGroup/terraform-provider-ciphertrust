package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMKeyMLDSA(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "mldsa_key" {
  name                 = "terraform-mldsa"
  algorithm            = "ml-dsa"
  ml_dsa_parameter_set = "ML-DSA-65"
  usage_mask           = 3
  undeletable          = false
  unexportable         = false
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.mldsa_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.mldsa_key", "algorithm", "ml-dsa"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.mldsa_key", "ml_dsa_parameter_set", "ML-DSA-65"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestResourceCMKeyMLDSA44(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "mldsa44_key" {
  name                 = "terraform-mldsa-44"
  algorithm            = "ml-dsa"
  ml_dsa_parameter_set = "ML-DSA-44"
  usage_mask           = 3
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.mldsa44_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.mldsa44_key", "ml_dsa_parameter_set", "ML-DSA-44"),
				),
			},
		},
	})
}

func TestResourceCMKeyMLDSA87(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "mldsa87_key" {
  name                 = "terraform-mldsa-87"
  algorithm            = "ml-dsa"
  ml_dsa_parameter_set = "ML-DSA-87"
  usage_mask           = 3
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.mldsa87_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.mldsa87_key", "ml_dsa_parameter_set", "ML-DSA-87"),
				),
			},
		},
	})
}
