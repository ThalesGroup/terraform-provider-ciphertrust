package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccCMGroupsListFilterConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name = %q
}

data "ciphertrust_cm_groups_list" "filtered" {
  filters    = { name = %q }
  depends_on = [ciphertrust_groups.test]
}
`, name, name)
}

func Test_CM_DataSourceCMGroupsList_FiltersHonored(t *testing.T) {
	RequireCM(t)
	name := "tfin419g-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMGroupsListFilterConfig(name),
				Check: checkStep(t, "filters honored",
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_groups_list.filtered", "groups.#", "1"),
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_groups_list.filtered", "groups.0.name", name),
				),
			},
		},
	})
}
