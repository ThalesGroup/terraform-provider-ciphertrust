package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicySecurityRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,

		Steps: []resource.TestStep{

			// CREATE + READ
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "test-policy-securityrule"
  policy_type = "Standard"
    security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy_security_rule" "secrule" {
  policy_id = ciphertrust_cte_policy.policy.id

  rule = {
    action         = "read"
    effect         = "deny"
    partial_match  = true
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_policy_security_rule.secrule",
						"rule.id",
					),
				),
			},

			// UPDATE + READ
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "test-policy-securityrule"
  policy_type = "Standard"
    security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy_security_rule" "secrule" {
  policy_id = ciphertrust_cte_policy.policy.id

  rule = {
    action                = "write"
    effect                = "permit"
    partial_match         = false
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_policy_security_rule.secrule",
						"rule.id",
					),
				),
			},

			// DELETE automatically tested
		},
	})
}
