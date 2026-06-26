package provider

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestCTEProcessSetsDataSource(t *testing.T) {
	processSetName := "tf-processset-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_process_set" "ps" {
			name        = "%s"
			description = "Created for CTE process sets data source test"
			processes = [
				{
					directory = "/usr/bin"
					file      = "python3"
				}
			]
		}

		data "ciphertrust_cte_process_sets" "ds" {
			depends_on = [ciphertrust_cte_process_set.ps]
		}
	`, processSetName)

	datasourceName := "data.ciphertrust_cte_process_sets.ds"
	resourceName := "ciphertrust_cte_process_set.ps"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Verify the list is populated
					resource.TestCheckResourceAttrSet(datasourceName, "process_sets.#"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[datasourceName]
						if !ok {
							return fmt.Errorf("not found: %s", datasourceName)
						}

						processSetsCountStr, ok := rs.Primary.Attributes["process_sets.#"]
						if !ok {
							return fmt.Errorf("process_sets.# not found in state")
						}

						processSetsCount, _ := strconv.Atoi(processSetsCountStr)
						found := false
						for i := 0; i < processSetsCount; i++ {
							nameKey := fmt.Sprintf("process_sets.%d.name", i)
							descKey := fmt.Sprintf("process_sets.%d.description", i)
							procDirKey := fmt.Sprintf("process_sets.%d.processes.0.directory", i)
							procFileKey := fmt.Sprintf("process_sets.%d.processes.0.file", i)

							if rs.Primary.Attributes[nameKey] == processSetName {
								found = true
								if rs.Primary.Attributes[descKey] != "Created for CTE process sets data source test" {
									return fmt.Errorf("expected description 'Created for CTE process sets data source test', got '%s'", rs.Primary.Attributes[descKey])
								}
								if rs.Primary.Attributes[procDirKey] != "/usr/bin" {
									return fmt.Errorf("expected process directory '/usr/bin', got '%s'", rs.Primary.Attributes[procDirKey])
								}
								if rs.Primary.Attributes[procFileKey] != "python3" {
									return fmt.Errorf("expected process file 'python3', got '%s'", rs.Primary.Attributes[procFileKey])
								}
								break
							}
						}

						if !found {
							return fmt.Errorf("process set %s not found in data source", processSetName)
						}

						return nil
					},
				),
			},
		},
	})
}
