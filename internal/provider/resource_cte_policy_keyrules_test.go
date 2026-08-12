package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

// cteKeyRuleResourceSetConfig renders a policy plus a key_rule whose
// resource_set_id is optionally set to the given resource set reference
// expression (or omitted/cleared when empty).
func cteKeyRuleResourceSetConfig(policyName, resourceSetIDExpr string) string {
	ruleBody := `
    key_id   = "clear_key"
    key_type = "name"
`
	if resourceSetIDExpr != "" {
		ruleBody += fmt.Sprintf("    resource_set_id = %s\n", resourceSetIDExpr)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "rs" {
  name = "tf-keyrule-rs-%s"
  resources = [{
    directory          = "/opt/tfin470"
    file               = "*"
    include_subfolders = true
    hdfs               = false
  }]
}

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
%s  }
}
`, policyName, policyName, ruleBody)
}

// TestCTEPolicyKeyRuleResource_resourceSetIDAndKeyTypeStability covers
// TFIN-470 (resource_set_id UUID->name normalization causes a perpetual plan
// diff) and TFIN-472 (key_type is never returned by CM GET, so Read() reset it
// to "" and produced a perpetual diff). After apply, a subsequent plan must be
// empty; without the fix, Read() overwrote rule.resource_set_id with the
// CM-normalized name and rule.key_type with "", so this step always failed.
func TestCTEPolicyKeyRuleResource_resourceSetIDAndKeyTypeStability(t *testing.T) {
	policyName := "tf-keyrule-rsid-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_key_rule.keyrule"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteKeyRuleResourceSetConfig(policyName, "ciphertrust_cte_resource_set.rs.id"),
				Check: checkStep(t, "key_rule: create with resource_set_id (UUID) and key_type",
					resource.TestCheckResourceAttrSet(rn, "rule.id"),
					resource.TestCheckResourceAttr(rn, "rule.key_type", "name"),
					resource.TestCheckResourceAttrPair(rn, "rule.resource_set_id", "ciphertrust_cte_resource_set.rs", "id"),
				),
			},
			// TFIN-470 + TFIN-472: plan must be empty; previously perpetually
			// proposed resource_set_id name->UUID and key_type ""->"name".
			{
				Config:             cteKeyRuleResourceSetConfig(policyName, "ciphertrust_cte_resource_set.rs.id"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// TFIN-471: clearing resource_set_id from config must actually
			// clear it on CM (previously Update() never sent the field due to
			// the empty-string check, so it silently no-opped).
			{
				Config: cteKeyRuleResourceSetConfig(policyName, ""),
				Check: checkStep(t, "key_rule: clear resource_set_id",
					resource.TestCheckResourceAttr(rn, "rule.resource_set_id", ""),
				),
			},
			// Re-affirm stability after the clear: no perpetual diff proposing
			// to re-clear an already-cleared value.
			{
				Config:             cteKeyRuleResourceSetConfig(policyName, ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTEPolicyKeyRuleResource_resourceSetIDDrift covers TFIN-610: an
// out-of-band change to rule.resource_set_id (e.g. a direct CM API PATCH)
// must be DETECTED on the next plan. TFIN-470's original fix made Read()
// preserve the existing state value for resource_set_id unconditionally
// (to stop a perpetual UUID<->name diff), which as a side effect meant
// genuine out-of-band resource_set_id changes were never detected at all --
// a silent-drift regression. Without TFIN-610's fix, the PlanOnly step below
// would show an empty plan despite the confirmed live PATCH.
func TestCTEPolicyKeyRuleResource_resourceSetIDDrift(t *testing.T) {
	policyName := "tf-keyrule-rsid-drift-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy_key_rule.keyrule"
	var policyID, ruleID, rs2ID string

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "rs" {
  name = "tf-keyrule-rsid-drift-rs-%s"
  resources = [{
    directory          = "/opt/tfin610"
    file               = "*"
    include_subfolders = true
    hdfs               = false
  }]
}

resource "ciphertrust_cte_resource_set" "rs2" {
  name = "tf-keyrule-rsid-drift-rs2-%s"
  resources = [{
    directory          = "/opt/tfin610-2"
    file               = "*"
    include_subfolders = true
    hdfs               = false
  }]
}

resource "ciphertrust_cte_policy" "policy" {
  name        = %q
  policy_type = "Standard"
  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy_key_rule" "keyrule" {
  policy_id = ciphertrust_cte_policy.policy.id
  rule = {
    key_id          = "clear_key"
    key_type        = "name"
    resource_set_id = ciphertrust_cte_resource_set.rs.id
  }
  # The out-of-band PATCH below rebinds this rule to rs2 without Terraform's
  # knowledge, creating a real CM-side dependency the HCL graph doesn't
  # express. Without this, destroy may attempt to delete rs2 before the rule
  # that (out-of-band) now references it, which CM rejects as "in use".
  depends_on = [ciphertrust_cte_resource_set.rs2]
}
`, policyName, policyName, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "key_rule resource_set_id drift: create",
					cteCaptureAttr(rn, "policy_id", &policyID),
					cteCaptureAttr(rn, "rule.id", &ruleID),
					cteCaptureAttr("ciphertrust_cte_resource_set.rs2", "id", &rs2ID),
				),
			},
			{
				PreConfig: func() {
					// Directly PATCH resource_set_id on CM to a *different*
					// resource set, bypassing Terraform entirely.
					cteOutOfBandPatch(common.URL_CTE_POLICY+"/"+policyID+"/keyrules", ruleID,
						fmt.Sprintf(`{"resource_set_id":%q}`, rs2ID))
				},
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
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
