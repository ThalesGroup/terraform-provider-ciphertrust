package provider

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"testing"
)

func TestCTEPolicyKeyRulesDataSource(t *testing.T) {
	policyName := "tf-policy-kr-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_policy" "test_policy" {
			name        = "%s"
			description = "Created for CTE policy key rules data source test"
			policy_type = "Standard"
			security_rules = [
				{
					action = "all_ops"
					effect = "permit,audit"
				}
			]
			key_rules = [
				{
					key_id = "clear_key"
				}
			]
		}

		data "ciphertrust_cte_policy_key_rules" "ds" {
			depends_on = [ciphertrust_cte_policy.test_policy]
			policy     = ciphertrust_cte_policy.test_policy.id
		}
	`, policyName)

	datasourceName := "data.ciphertrust_cte_policy_key_rules.ds"
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
					resource.TestCheckResourceAttr(datasourceName, "rules.0.key_id", "clear_key"),
					resource.TestCheckResourceAttrPair(datasourceName, "rules.0.policy_id", resourceName, "id"),
				),
			},
		},
	})
}
