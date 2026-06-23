package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTECSIGroup(t *testing.T) {
	name := "test-csi-group-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create CSI Group
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = %q
  kubernetes_namespace     = "default"
  kubernetes_storage_class = "standard"
  description    = "initial description"
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_csigroup.csigroup", "id"),
				),
			},

			// Step 2: Update CSI Group (only description using op_type = update)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = %q
  kubernetes_namespace     = "default"
  kubernetes_storage_class = "standard"

  op_type = "update"

  description    = "updated description"
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_csigroup.csigroup", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
