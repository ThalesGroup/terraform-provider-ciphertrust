package provider

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestCTECSIGroupDataSource(t *testing.T) {
	csiGroupName := "tf-csi-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_csigroup" "csi" {
			name                     = "%s"
			description              = "Created for CTE CSI group data source test"
			kubernetes_namespace     = "default"
			kubernetes_storage_class = "standard"
		}

		data "ciphertrust_cte_csi_group" "ds" {
			depends_on = [ciphertrust_cte_csigroup.csi]
		}
	`, csiGroupName)

	datasourceName := "data.ciphertrust_cte_csi_group.ds"
	resourceName := "ciphertrust_cte_csigroup.csi"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Verify the list is populated
					resource.TestCheckResourceAttrSet(datasourceName, "csi_group.#"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[datasourceName]
						if !ok {
							return fmt.Errorf("not found: %s", datasourceName)
						}

						csiGroupsCountStr, ok := rs.Primary.Attributes["csi_group.#"]
						if !ok {
							return fmt.Errorf("csi_group.# not found in state")
						}

						csiGroupsCount, _ := strconv.Atoi(csiGroupsCountStr)
						found := false
						for i := 0; i < csiGroupsCount; i++ {
							nameKey := fmt.Sprintf("csi_group.%d.name", i)
							descKey := fmt.Sprintf("csi_group.%d.description", i)
							nsKey := fmt.Sprintf("csi_group.%d.k8s_namespace", i)
							scKey := fmt.Sprintf("csi_group.%d.k8s_storage_class", i)

							if rs.Primary.Attributes[nameKey] == csiGroupName {
								found = true
								if rs.Primary.Attributes[descKey] != "Created for CTE CSI group data source test" {
									return fmt.Errorf("expected description 'Created for CTE CSI group data source test', got '%s'", rs.Primary.Attributes[descKey])
								}
								if rs.Primary.Attributes[nsKey] != "default" {
									return fmt.Errorf("expected k8s_namespace 'default', got '%s'", rs.Primary.Attributes[nsKey])
								}
								if rs.Primary.Attributes[scKey] != "standard" {
									return fmt.Errorf("expected k8s_storage_class 'standard', got '%s'", rs.Primary.Attributes[scKey])
								}
								break
							}
						}

						if !found {
							return fmt.Errorf("csi group %s not found in data source", csiGroupName)
						}

						return nil
					},
				),
			},
		},
	})
}
