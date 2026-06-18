package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicyDataTXRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create Standard Policy with Key Rule (clear_key)
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "test-policy-datatx"
  policy_type = "Standard"

  security_rules = [{
    effect = "permit"
    action = "key_op"
  }]

  key_rules = [{
    key_id   = "clear_key"
    key_type = ""
  }]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy.policy", "id"),
				),
			},

			// Step 2: Add Data TX Rule (clear_key)
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "test-policy-datatx"
  policy_type = "Standard"

  security_rules = [{
    effect = "permit"
    action = "key_op"
  }]

  key_rules = [{
    key_id   = "clear_key"
    key_type = ""
  }]
}

resource "ciphertrust_cte_policy_data_tx_rule" "datatx" {
  policy_id = ciphertrust_cte_policy.policy.id

  rule = {
    key_id   = "clear_key"
    key_type = ""
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy_data_tx_rule.datatx", "rule.id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
