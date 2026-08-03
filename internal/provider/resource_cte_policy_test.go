package provider

import (
	"fmt"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"regexp"
	"testing"
)

// cteStandardPolicyConfig renders a Standard ciphertrust_cte_policy with a single
// security rule. action varies the security rule so the update step produces a
// real change.
func cteStandardPolicyConfig(name, description, action string) string {
	desc := ""
	if description != "" {
		desc = fmt.Sprintf("  description = %q\n", description)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "cte_policy" {
  name        = %q
  policy_type = "Standard"
  never_deny  = false
%s  security_rules = [
    {
      effect        = "permit"
      action        = %q
      partial_match = false
    }
  ]
}
`, name, desc, action)
}

// TestCTEPolicyResource exercises Create -> Read -> Update -> Delete plus plan
// stability and import. policy_type and name are immutable, so only description
// and the security rule action change across steps.
func TestCTEPolicyResource(t *testing.T) {
	name := "tf-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteStandardPolicyConfig(name, "Created via TF", "all_ops"),
				Check: checkStep(t, "policy: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy.cte_policy", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy", "policy_type", "Standard"),
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy", "security_rules.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy", "security_rules.0.action", "all_ops"),
				),
			},
			{
				Config:             cteStandardPolicyConfig(name, "Created via TF", "all_ops"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cteStandardPolicyConfig(name, "Updated via TF", "read"),
				Check: checkStep(t, "policy: update",
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy", "description", "Updated via TF"),
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy", "security_rules.0.action", "read"),
				),
			},
			{
				Config:             cteStandardPolicyConfig(name, "Updated via TF", "read"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				ResourceName:      "ciphertrust_cte_policy.cte_policy",
				ImportState:       true,
				ImportStateVerify: true,
				// security_rules order/computed sub-ids can vary on round-trip;
				// verify the stable, user-facing fields instead of the full tree.
				ImportStateVerifyIgnore: []string{"security_rules"},
			},
		},
	})
}

// TestCTEPolicyResource_nameRequiresReplace verifies a name change is planned
// as a destroy+create rather than an in-place update (TFIN-495).
func TestCTEPolicyResource_nameRequiresReplace(t *testing.T) {
	name := "tf-policy-imm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy.cte_policy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteStandardPolicyConfig(name, "Original", "all_ops"),
				Check: checkStep(t, "policy requires replace: create",
					resource.TestCheckResourceAttr(rn, "name", name),
				),
			},
			{
				Config: cteStandardPolicyConfig(name+"-renamed", "Original", "all_ops"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(rn, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "policy requires replace: rename",
					resource.TestCheckResourceAttr(rn, "name", name+"-renamed"),
				),
			},
		},
	})
}

// TestCTEPolicyResource_drift is the drift-detection test for the "policy"
// category: mutate the description out-of-band, then assert a non-empty plan.
func TestCTEPolicyResource_drift(t *testing.T) {
	name := "tf-policy-drift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteStandardPolicyConfig(name, "Drift original", "all_ops"),
				Check: checkStep(t, "policy drift: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy", "description", "Drift original"),
					cteCaptureID("ciphertrust_cte_policy.cte_policy", &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_POLICY, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteStandardPolicyConfig(name, "Drift original", "all_ops"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// ctePolicyTypedConfig renders a policy with an explicit policy_type, used by the
// policy_type-immutability test.
func ctePolicyTypedConfig(name, policyType string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "cte_policy" {
  name        = %q
  policy_type = %q
  never_deny  = false
  security_rules = [
    {
      effect        = "permit"
      action        = "all_ops"
      partial_match = false
    }
  ]
}
`, name, policyType)
}

// TestCTEPolicyResource_typeImmutable verifies a change to the (immutable)
// policy_type is planned as a destroy+create replacement rather than a
// misleading in-place update that then fails at apply (TFIN-546).
func TestCTEPolicyResource_typeImmutable(t *testing.T) {
	name := "tf-policy-typeimm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_policy.cte_policy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: ctePolicyTypedConfig(name, "Standard"),
				Check: checkStep(t, "policy type immutable: create",
					resource.TestCheckResourceAttr(rn, "policy_type", "Standard"),
				),
			},
			{
				// CSI, like Standard, only requires security_rules; other
				// non-Standard types (e.g. LDT) require additional
				// mandatory nested rule blocks tied to real key material.
				Config: ctePolicyTypedConfig(name, "CSI"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(rn, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "policy type immutable: replace",
					resource.TestCheckResourceAttr(rn, "policy_type", "CSI"),
				),
			},
		},
	})
}

// cteApplykeyPolicyConfig renders a Standard ciphertrust_cte_policy whose
// single security rule's effect and never_deny are both parameterized, used
// to exercise the TFIN-496 never_deny/applykey cross-field validation.
func cteApplykeyPolicyConfig(name string, neverDeny bool, effect string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "cte_policy_applykey" {
  name        = %q
  policy_type = "Standard"
  never_deny  = %t

  key_rules = [{
    key_id = "clear_key"
  }]

  security_rules = [
    {
      effect        = %q
      action        = "all_ops"
      partial_match = false
    }
  ]
}
`, name, neverDeny, effect)
}

// TestCTEPolicyResource_neverDenyApplykeyValidation verifies that a
// security_rules.effect containing "applykey" is rejected at plan time when
// never_deny = false, since CipherTrust Manager silently strips "applykey"
// server-side in that case, which otherwise produces a permanent
// plan/apply loop (TFIN-496).
func TestCTEPolicyResource_neverDenyApplykeyValidation(t *testing.T) {
	name := "tf-policy-applykey-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// never_deny = false + applykey must be rejected at plan time.
				Config:      cteApplykeyPolicyConfig(name, false, "deny,applykey"),
				ExpectError: regexp.MustCompile(`(?i)Invalid security_rules\.effect with never_deny = false`),
			},
			{
				// never_deny = true + applykey is valid and must succeed.
				Config: cteApplykeyPolicyConfig(name, true, "deny,applykey"),
				Check: checkStep(t, "policy applykey validation: never_deny=true allowed",
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy_applykey", "never_deny", "true"),
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy_applykey", "security_rules.0.effect", "deny,applykey"),
				),
			},
			{
				// never_deny = false without applykey is valid and must succeed.
				Config: cteApplykeyPolicyConfig(name, false, "deny"),
				Check: checkStep(t, "policy applykey validation: never_deny=false without applykey allowed",
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy_applykey", "never_deny", "false"),
					resource.TestCheckResourceAttr("ciphertrust_cte_policy.cte_policy_applykey", "security_rules.0.effect", "deny"),
				),
			},
		},
	})
}
