package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTELDTGroupComm(t *testing.T) {
	name := "testLDTGroup1-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_ldtgroupcomms" "ldt" {
  name        = %q
  description = "Initial LDT group comm service"
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_ldtgroupcomms.ldt", "id"),
				),
			},

			// Step 2: Update
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_ldtgroupcomms" "ldt" {
  name        = %q
  description = "Updated LDT group comm service"
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_ldtgroupcomms.ldt", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
