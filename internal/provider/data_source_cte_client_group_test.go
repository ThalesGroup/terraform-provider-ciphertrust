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

func TestCTEClientGroupDataSource(t *testing.T) {
	clientGroupName := "tf-cg-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_client_group" "cg" {
			name        = "%s"
			description = "Created for CTE client group data source test"
			cluster_type = "NON-CLUSTER"
		}

		data "ciphertrust_cte_client_group" "ds" {
			depends_on = [ciphertrust_cte_client_group.cg]
		}
	`, clientGroupName)

	datasourceName := "data.ciphertrust_cte_client_group.ds"
	resourceName := "ciphertrust_cte_client_group.cg"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// The API returns all client groups, verify the list is populated
					resource.TestCheckResourceAttrSet(datasourceName, "client_groups.#"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[datasourceName]
						if !ok {
							return fmt.Errorf("not found: %s", datasourceName)
						}

						clientGroupsCountStr, ok := rs.Primary.Attributes["client_groups.#"]
						if !ok {
							return fmt.Errorf("client_groups.# not found in state")
						}

						clientGroupsCount, _ := strconv.Atoi(clientGroupsCountStr)
						found := false
						for i := 0; i < clientGroupsCount; i++ {
							nameKey := fmt.Sprintf("client_groups.%d.name", i)
							descKey := fmt.Sprintf("client_groups.%d.description", i)
							clusterTypeKey := fmt.Sprintf("client_groups.%d.cluster_type", i)

							if rs.Primary.Attributes[nameKey] == clientGroupName {
								found = true
								if rs.Primary.Attributes[descKey] != "Created for CTE client group data source test" {
									return fmt.Errorf("expected description 'Created for CTE client group data source test', got '%s'", rs.Primary.Attributes[descKey])
								}
								if rs.Primary.Attributes[clusterTypeKey] != "NON-CLUSTER" {
									return fmt.Errorf("expected cluster_type 'NON-CLUSTER', got '%s'", rs.Primary.Attributes[clusterTypeKey])
								}
								break
							}
						}

						if !found {
							return fmt.Errorf("client group %s not found in data source", clientGroupName)
						}

						return nil
					},
				),
			},
		},
	})
}
