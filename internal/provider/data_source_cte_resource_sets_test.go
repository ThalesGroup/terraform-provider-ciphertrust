// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestCTEResourceSetsDataSource(t *testing.T) {
	resourceSetName := "tf-resourceset-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_resource_set" "rs" {
			name        = "%s"
			description = "Created for CTE resource sets data source test"
			resources = [
				{
					directory = "/tmp/guarded"
				}
			]
		}

		data "ciphertrust_cte_resource_sets" "ds" {
			depends_on = [ciphertrust_cte_resource_set.rs]
		}
	`, resourceSetName)

	datasourceName := "data.ciphertrust_cte_resource_sets.ds"
	resourceName := "ciphertrust_cte_resource_set.rs"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Verify the list is populated
					resource.TestCheckResourceAttrSet(datasourceName, "resource_sets.#"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[datasourceName]
						if !ok {
							return fmt.Errorf("not found: %s", datasourceName)
						}

						resourceSetsCountStr, ok := rs.Primary.Attributes["resource_sets.#"]
						if !ok {
							return fmt.Errorf("resource_sets.# not found in state")
						}

						resourceSetsCount, _ := strconv.Atoi(resourceSetsCountStr)
						found := false
						for i := 0; i < resourceSetsCount; i++ {
							nameKey := fmt.Sprintf("resource_sets.%d.name", i)
							descKey := fmt.Sprintf("resource_sets.%d.description", i)
							resourceDirKey := fmt.Sprintf("resource_sets.%d.resources.0.directory", i)

							if rs.Primary.Attributes[nameKey] == resourceSetName {
								found = true
								if rs.Primary.Attributes[descKey] != "Created for CTE resource sets data source test" {
									return fmt.Errorf("expected description 'Created for CTE resource sets data source test', got '%s'", rs.Primary.Attributes[descKey])
								}
								if rs.Primary.Attributes[resourceDirKey] != "/tmp/guarded" {
									return fmt.Errorf("expected resource directory '/tmp/guarded', got '%s'", rs.Primary.Attributes[resourceDirKey])
								}
								break
							}
						}

						if !found {
							return fmt.Errorf("resource set %s not found in data source", resourceSetName)
						}

						return nil
					},
				),
			},
		},
	})
}
