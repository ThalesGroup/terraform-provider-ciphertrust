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

// cteSignatureRuleConfig renders a signature set, a Standard policy, and a
// ciphertrust_cte_policy_signature_rule attaching the set to the policy. The set
// is referenced by name because Read repopulates signature_set_id_list from the
// API's resolved signature-set name, so a name reference keeps the plan stable.
func cteSignatureRuleConfig(policyName, sigSetName string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "sigset" {
  name        = %q
  type        = "Container-Image"
  source_list = ["/usr/bin"]
}

resource "ciphertrust_cte_policy" "policy" {
  name        = %q
  policy_type = "CSI"
  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy_signature_rule" "sigrule" {
  policy_id             = ciphertrust_cte_policy.policy.id
  signature_set_id_list = [ciphertrust_cte_signature_set.sigset.name]
}
`, sigSetName, policyName)
}

func TestCTEPolicySignatureRuleResource(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "tf-sigrule-" + suffix
	sigSetName := "tf-sigrule-set-" + suffix
	const rn = "ciphertrust_cte_policy_signature_rule.sigrule"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSignatureRuleConfig(policyName, sigSetName),
				Check: checkStep(t, "signature_rule: create",
					resource.TestCheckResourceAttrSet(rn, "policy_id"),
					resource.TestCheckResourceAttr(rn, "ids.#", "1"),
					resource.TestCheckResourceAttr(rn, "signature_set_id_list.#", "1"),
				),
			},
			{
				Config:             cteSignatureRuleConfig(policyName, sigSetName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Import via composite "<policy_id>:<signature_rule_id>".
			{
				ResourceName:      rn,
				ImportState:       true,
				ImportStateIdFunc: cteRuleImportID(rn, "ids.0"),
				ImportStateCheck:  importStateCheckAttrsSet("policy_id", "ids.0"),
			},
		},
	})
}

// TestCTEPolicySignatureRuleResource_missingPolicyID is the negative path:
// omitting the required policy_id fails at plan time.
func TestCTEPolicySignatureRuleResource_missingPolicyID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy_signature_rule" "sigrule" {
  signature_set_id_list = []
}
`,
				ExpectError: regexp.MustCompile(`(?i)policy_id`),
			},
		},
	})
}
