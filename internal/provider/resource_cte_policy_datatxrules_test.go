package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteDataTXRuleConfig renders a Standard policy (with a key rule, required for
// data-transformation) plus a standalone ciphertrust_cte_policy_data_tx_rule.
func cteDataTXRuleConfig(policyName string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "policy" {
  name        = %q
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
`, policyName)
}

func TestResourceCTEPolicyDataTXRule(t *testing.T) {
	policyName := "tf-datatx-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_data_tx_rule.datatx"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteDataTXRuleConfig(policyName),
				Check: checkStep(t, "data_tx_rule: create",
					resource.TestCheckResourceAttrSet(rn, "rule.id"),
					resource.TestCheckResourceAttrSet(rn, "policy_id"),
				),
			},
			{
				Config:             cteDataTXRuleConfig(policyName),
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

// TestResourceCTEPolicyDataTXRule_missingPolicyID: omitting required policy_id fails at plan.
func TestResourceCTEPolicyDataTXRule_missingPolicyID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy_data_tx_rule" "datatx" {
  rule = {
    key_id   = "clear_key"
    key_type = ""
  }
}
`,
				ExpectError: regexp.MustCompile(`(?i)policy_id`),
			},
		},
	})
}
