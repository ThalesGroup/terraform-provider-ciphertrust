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

func TestCTEUserSetsDataSource(t *testing.T) {
	userSetName := "tf-userset-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_user_set" "userset" {
			name        = "%s"
			description = "Created for CTE user sets data source test"
			users = [
				{
					uname = "root"
					uid   = 0
				}
			]
		}

		data "ciphertrust_cte_usersets" "ds" {
			depends_on = [ciphertrust_cte_user_set.userset]
		}
	`, userSetName)

	datasourceName := "data.ciphertrust_cte_usersets.ds"
	resourceName := "ciphertrust_cte_user_set.userset"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Verify the list is populated
					resource.TestCheckResourceAttrSet(datasourceName, "user_sets.#"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[datasourceName]
						if !ok {
							return fmt.Errorf("not found: %s", datasourceName)
						}

						userSetsCountStr, ok := rs.Primary.Attributes["user_sets.#"]
						if !ok {
							return fmt.Errorf("user_sets.# not found in state")
						}

						userSetsCount, _ := strconv.Atoi(userSetsCountStr)
						found := false
						for i := 0; i < userSetsCount; i++ {
							nameKey := fmt.Sprintf("user_sets.%d.name", i)
							descKey := fmt.Sprintf("user_sets.%d.description", i)

							if rs.Primary.Attributes[nameKey] == userSetName {
								found = true
								if rs.Primary.Attributes[descKey] != "Created for CTE user sets data source test" {
									return fmt.Errorf("expected description 'Created for CTE user sets data source test', got '%s'", rs.Primary.Attributes[descKey])
								}
								break
							}
						}

						if !found {
							return fmt.Errorf("user set %s not found in data source", userSetName)
						}

						return nil
					},
				),
			},
		},
	})
}
