package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccCMKey_mlDsa creates a ciphertrust_cm_key using the post-quantum
// ML-DSA signature algorithm and lets the framework destroy it. ML-DSA is a
// post-quantum signature algorithm; supported parameter sets are 44, 65, 87.
// Per TFIN-174 the resource Read() is a no-op, so no read assertions beyond
// the framework's auto-checks are made.
func TestAccCMKey_mlDsa(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "mldsa_key" {
  name       = "terraform-mldsa"
  algorithm  = "ml-dsa"
  key_size   = 65
  usage_mask = 3
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.mldsa_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.mldsa_key", "algorithm", "ml-dsa"),
				),
			},
		},
	})
}
