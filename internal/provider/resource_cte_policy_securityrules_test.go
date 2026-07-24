// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteSecurityRuleConfig renders a Standard policy plus a standalone
// ciphertrust_cte_policy_security_rule attached to it. action/effect vary so the
// update step produces a real change.
func cteSecurityRuleConfig(policyName, action, effect string, partialMatch bool) string {
	return providerConfig + fmt.Sprintf(`
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
    action        = %q
    effect        = %q
    partial_match = %t
  }
}
`, policyName, action, effect, partialMatch)
}

func TestCTEPolicySecurityRuleResource(t *testing.T) {
	policyName := "tf-secrule-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_security_rule.secrule"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSecurityRuleConfig(policyName, "read", "deny", true),
				Check: checkStep(t, "security_rule: create",
					resource.TestCheckResourceAttrSet(rn, "rule.id"),
					resource.TestCheckResourceAttrSet(rn, "policy_id"),
					resource.TestCheckResourceAttr(rn, "rule.action", "read"),
				),
			},
			{
				Config: cteSecurityRuleConfig(policyName, "write", "permit", false),
				Check: checkStep(t, "security_rule: update",
					resource.TestCheckResourceAttr(rn, "rule.action", "write"),
					resource.TestCheckResourceAttr(rn, "rule.effect", "permit"),
				),
			},
			{
				Config:             cteSecurityRuleConfig(policyName, "write", "permit", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				ResourceName:      rn,
				ImportState:       true,
				ImportStateIdFunc: cteRuleImportID(rn, "rule.id"),
				ImportStateCheck:  importStateCheckAttrsSet("policy_id", "rule.id"),
			},
		},
	})
}

// TestCTEPolicySecurityRuleResource_missingPolicyID is the negative-path test:
// omitting the required policy_id must fail at plan time.
func TestCTEPolicySecurityRuleResource_missingPolicyID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy_security_rule" "secrule" {
  rule = {
    action = "read"
    effect = "permit"
  }
}
`,
				ExpectError: regexp.MustCompile(`(?i)policy_id`),
			},
		},
	})
}

// TestCTEPolicySecurityRuleResource_drift is the drift-detection test for the
// "rule" category: change the rule's effect out-of-band, then assert the next
// plan is non-empty.
func TestCTEPolicySecurityRuleResource_drift(t *testing.T) {
	policyName := "tf-secrule-drift-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_security_rule.secrule"
	var policyID, ruleID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSecurityRuleConfig(policyName, "read", "permit", false),
				Check: checkStep(t, "security_rule drift: create",
					cteCaptureAttr(rn, "policy_id", &policyID),
					cteCaptureAttr(rn, "rule.id", &ruleID),
				),
			},
			{
				PreConfig: func() {
					// PATCH the rule on the parent policy out-of-band.
					cteOutOfBandPatch(common.URL_CTE_POLICY+"/"+policyID+"/securityrules", ruleID, `{"effect":"deny"}`)
				},
				Config:             cteSecurityRuleConfig(policyName, "read", "permit", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
