package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCTEPolicySecurityRulesDataSource(t *testing.T) {
	policyName := "tf-policy-sec-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_policy" "test_policy" {
			name        = "%s"
			description = "Created for CTE policy security rules data source test"
			policy_type = "Standard"
			security_rules = [
				{
					action = "all_ops"
					effect = "permit,audit"
					partial_match = true
				}
			]
		}

		data "ciphertrust_cte_policy_security_rules" "ds" {
			depends_on = [ciphertrust_cte_policy.test_policy]
			policy     = ciphertrust_cte_policy.test_policy.id
		}
	`, policyName)

	datasourceName := "data.ciphertrust_cte_policy_security_rules.ds"
	resourceName := "ciphertrust_cte_policy.test_policy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),

					resource.TestCheckResourceAttr(datasourceName, "rules.#", "1"),
					resource.TestCheckResourceAttrSet(datasourceName, "rules.0.id"),
					resource.TestCheckResourceAttr(datasourceName, "rules.0.action", "all_ops"),
					resource.TestCheckResourceAttr(datasourceName, "rules.0.effect", "permit,audit"),
					resource.TestCheckResourceAttrPair(datasourceName, "rules.0.policy_id", resourceName, "id"),
				),
			},
		},
	})
}
