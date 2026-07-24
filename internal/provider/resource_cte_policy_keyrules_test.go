// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteKeyRuleConfig renders a Standard policy plus a standalone
// ciphertrust_cte_policy_key_rule attached to it.
func cteKeyRuleConfig(policyName, keyID string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "policy" {
  name        = %q
  policy_type = "Standard"
  description = "Initial policy"
  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy_key_rule" "keyrule" {
  policy_id = ciphertrust_cte_policy.policy.id
  rule = {
    key_id = %q
  }
}
`, policyName, keyID)
}

func TestCTEPolicyKeyRuleResource(t *testing.T) {
	policyName := "tf-keyrule-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_key_rule.keyrule"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteKeyRuleConfig(policyName, "clear_key"),
				Check: checkStep(t, "key_rule: create",
					resource.TestCheckResourceAttrSet(rn, "rule.id"),
					resource.TestCheckResourceAttrSet(rn, "policy_id"),
				),
			},
			// Plan stability: re-applying yields no diff.
			{
				Config:             cteKeyRuleConfig(policyName, "clear_key"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Import via composite "<policy_id>:<rule_id>".
			{
				ResourceName:      rn,
				ImportState:       true,
				ImportStateIdFunc: cteRuleImportID(rn, "rule.id"),
				ImportStateCheck:  importStateCheckAttrsSet("policy_id", "rule.id"),
			},
		},
	})
}

// TestCTEPolicyKeyRuleResource_missingPolicyID: omitting required policy_id fails at plan.
func TestCTEPolicyKeyRuleResource_missingPolicyID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy_key_rule" "keyrule" {
  rule = {
    key_id = "clear_key"
  }
}
`,
				ExpectError: regexp.MustCompile(`(?i)policy_id`),
			},
		},
	})
}
