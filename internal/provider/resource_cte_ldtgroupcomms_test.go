package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTELDTGroupComm(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create
			{
				Config: providerConfig + `
resource "ciphertrust_cte_ldtgroupcomms" "ldt" {
  name        = "testLDTGroup1"
  description = "Initial LDT group comm service"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_ldtgroupcomms.ldt", "id"),
				),
			},

			// Step 2: Update
			{
				Config: providerConfig + `
resource "ciphertrust_cte_ldtgroupcomms" "ldt" {
  name        = "testLDTGroup1"
  description = "Updated LDT group comm service"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_ldtgroupcomms.ldt", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
