package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTECSIGroup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create CSI Group
			{
				Config: providerConfig + `
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = "test-csi-group"
  kubernetes_namespace     = "default"
  kubernetes_storage_class = "standard"
  description    = "initial description"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_csigroup.csigroup", "id"),
				),
			},

			// Step 2: Update CSI Group (only description using op_type = update)
			{
				Config: providerConfig + `
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = "test-csi-group"
  kubernetes_namespace     = "default"
  kubernetes_storage_class = "standard"

  op_type = "update"

  description    = "updated description"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_csigroup.csigroup", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
