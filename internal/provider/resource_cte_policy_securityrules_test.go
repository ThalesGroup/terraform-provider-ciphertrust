package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicySecurityRule(t *testing.T) {
	name := "test-policy-secrule-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,

		Steps: []resource.TestStep{

			// CREATE + READ
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "policy" {
  name        = %q
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
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_policy_security_rule.secrule",
						"rule.id",
					),
				),
			},

			// UPDATE + READ
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "policy" {
  name        = %q
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
`, name),
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
