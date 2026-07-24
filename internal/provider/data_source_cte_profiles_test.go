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

func TestCTEProfilesDataSource(t *testing.T) {
	profileName := "tf-profile-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_profile" "profile" {
			name            = "%s"
			description     = "Created for CTE profiles data source test"
			concise_logging = true
			connect_timeout = 30
		}

		data "ciphertrust_cte_profiles" "ds" {
			depends_on = [ciphertrust_cte_profile.profile]
		}
	`, profileName)

	datasourceName := "data.ciphertrust_cte_profiles.ds"
	resourceName := "ciphertrust_cte_profile.profile"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Verify the list is populated
					resource.TestCheckResourceAttrSet(datasourceName, "cte_profiles.#"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[datasourceName]
						if !ok {
							return fmt.Errorf("not found: %s", datasourceName)
						}

						profilesCountStr, ok := rs.Primary.Attributes["cte_profiles.#"]
						if !ok {
							return fmt.Errorf("cte_profiles.# not found in state")
						}

						profilesCount, _ := strconv.Atoi(profilesCountStr)
						found := false
						for i := 0; i < profilesCount; i++ {
							nameKey := fmt.Sprintf("cte_profiles.%d.name", i)
							descKey := fmt.Sprintf("cte_profiles.%d.description", i)
							conciseKey := fmt.Sprintf("cte_profiles.%d.concise_logging", i)
							timeoutKey := fmt.Sprintf("cte_profiles.%d.connect_timeout", i)

							if rs.Primary.Attributes[nameKey] == profileName {
								found = true
								if rs.Primary.Attributes[descKey] != "Created for CTE profiles data source test" {
									return fmt.Errorf("expected description 'Created for CTE profiles data source test', got '%s'", rs.Primary.Attributes[descKey])
								}
								if rs.Primary.Attributes[conciseKey] != "true" {
									return fmt.Errorf("expected concise_logging 'true', got '%s'", rs.Primary.Attributes[conciseKey])
								}
								if rs.Primary.Attributes[timeoutKey] != "30" {
									return fmt.Errorf("expected connect_timeout '30', got '%s'", rs.Primary.Attributes[timeoutKey])
								}
								break
							}
						}

						if !found {
							return fmt.Errorf("profile %s not found in data source", profileName)
						}

						return nil
					},
				),
			},
		},
	})
}
