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

// TestCTEPolicySecurityRuleResource_readNotFoundErrors verifies TFIN-623:
// deleting the security rule out-of-band and refreshing must now fail
// loudly (hard error) instead of the previous silent `response == ""`
// misdetection, which emitted zero diagnostic and wiped the rule from
// state. The rule must remain in Terraform state after the failed refresh.
func TestCTEPolicySecurityRuleResource_readNotFoundErrors(t *testing.T) {
	policyName := "tf-secrule-404-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_security_rule.secrule"
	var policyID, ruleID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSecurityRuleConfig(policyName, "read", "permit", false),
				Check: checkStep(t, "security_rule 404: create",
					cteCaptureAttr(rn, "policy_id", &policyID),
					cteCaptureAttr(rn, "rule.id", &ruleID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandDelete(common.URL_CTE_POLICY+"/"+policyID+"/securityrules", ruleID)
				},
				Config:      cteSecurityRuleConfig(policyName, "read", "permit", false),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)CTE Policy Security Rule .* not found`),
			},
		},
	})
}

// cteSecurityRuleResourceSetConfig renders a policy plus a security_rule whose
// resource_set_id is set to the given resource set reference expression.
func cteSecurityRuleResourceSetConfig(policyName, resourceSetIDExpr string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "rs" {
  name = "tf-secrule-rs-%s"
  resources = [{
    directory          = "/opt/tfin610"
    file               = "*"
    include_subfolders = true
    hdfs               = false
  }]
}

resource "ciphertrust_cte_policy" "policy" {
  name        = %q
  policy_type = "Standard"
  key_rules = [{
    key_id   = "clear_key"
    key_type = ""
  }]
}

resource "ciphertrust_cte_policy_security_rule" "secrule" {
  policy_id = ciphertrust_cte_policy.policy.id
  rule = {
    effect          = "permit"
    action          = "all_ops"
    resource_set_id = %s
  }
}
`, policyName, policyName, resourceSetIDExpr)
}

// TestCTEPolicySecurityRuleResource_resourceSetIDStability covers TFIN-610's
// milder, VISIBLE variant on ciphertrust_cte_policy_security_rule (not
// covered by TFIN-470/471, which only fixed data_tx_rule/key_rule): CM's GET
// always returns the resource set's name, and Read() has always
// unconditionally refreshed state from it, so a config supplying a UUID
// showed a permanent, non-converging diff on every subsequent plan. After
// apply, a further plan must be empty.
func TestCTEPolicySecurityRuleResource_resourceSetIDStability(t *testing.T) {
	policyName := "tf-secrule-rsid-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_security_rule.secrule"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSecurityRuleResourceSetConfig(policyName, "ciphertrust_cte_resource_set.rs.id"),
				Check: checkStep(t, "security_rule: create with resource_set_id (UUID)",
					resource.TestCheckResourceAttrSet(rn, "rule.id"),
					resource.TestCheckResourceAttrPair(rn, "rule.resource_set_id", "ciphertrust_cte_resource_set.rs", "id"),
				),
			},
			// TFIN-610: plan must be empty; previously perpetually proposed
			// resource_set_id name->UUID on every refresh.
			{
				Config:             cteSecurityRuleResourceSetConfig(policyName, "ciphertrust_cte_resource_set.rs.id"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
