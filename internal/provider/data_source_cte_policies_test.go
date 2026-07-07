package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCTEPoliciesDataSource(t *testing.T) {
	policyName := "tf-policy-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_policy" "test_policy" {
			name        = "%s"
			description = "Created for CTE policies data source test"
			policy_type = "Standard"
			security_rules = [
				{
					action = "all_ops"
					effect = "permit,audit"
				}
			]
		}

		data "ciphertrust_cte_policies_list" "ds" {
			depends_on  = [ciphertrust_cte_policy.test_policy]
			policy_name = ciphertrust_cte_policy.test_policy.name
		}
	`, policyName)

	datasourceName := "data.ciphertrust_cte_policies_list.ds"
	resourceName := "ciphertrust_cte_policy.test_policy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					// Validate the resource is created
					resource.TestCheckResourceAttrSet(resourceName, "id"),

					// Validate the data source filtering and attributes
					resource.TestCheckResourceAttr(datasourceName, "cte_policies.#", "1"),
					resource.TestCheckResourceAttrPair(datasourceName, "cte_policies.0.id", resourceName, "id"),
					resource.TestCheckResourceAttr(datasourceName, "cte_policies.0.name", policyName),
					resource.TestCheckResourceAttr(datasourceName, "cte_policies.0.description", "Created for CTE policies data source test"),
					resource.TestCheckResourceAttr(datasourceName, "cte_policies.0.policy_type", "STANDARD"),
				),
			},
		},
	})
}
