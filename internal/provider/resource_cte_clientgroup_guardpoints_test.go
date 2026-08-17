package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

const cteClientGroupGPName = "ciphertrust_cte_clientgroup_guardpoint.gp"

// cteClientGroupGPConfig renders a policy + client group + clientgroup guardpoint.
// extraGP is the guard_points map body.
func cteClientGroupGPConfig(policyName, cgName, extraGP string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "policy" {
  name        = %q
  policy_type = "Standard"
  description = "Created via TF test"
  never_deny  = true
  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Created via TF test"
}

resource "ciphertrust_cte_clientgroup_guardpoint" "gp" {
  client_group_id = ciphertrust_cte_client_group.cg.id
  guard_points = {
    %s
  }
}
`, policyName, cgName, extraGP)
}

func cteCGGuardPoint(path, guardEnabled string) string {
	return fmt.Sprintf(`%q = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id%s
      }
    }`, path, guardEnabled)
}

func TestCTEClientGroupGuardPointResource(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "TF_CTE_Policy_CG_Test-" + suffix
	cgName := "TF_CTE_ClientGroup_Test-" + suffix

	baseChecks := resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(cteClientGroupGPName, "id"),
		resource.TestCheckResourceAttrSet(cteClientGroupGPName, "client_group_id"),
	)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create.
			{
				Config: cteClientGroupGPConfig(policyName, cgName, cteCGGuardPoint("/tmp/testpathcg1", "")),
				Check:  checkStep(t, "clientgroup_guardpoint: create", baseChecks),
			},
			// Step 2: Disable guard_enabled and read it back.
			{
				Config: cteClientGroupGPConfig(policyName, cgName, cteCGGuardPoint("/tmp/testpathcg1", "\n        guard_enabled    = false")),
				Check: checkStep(t, "clientgroup_guardpoint: update guard_enabled",
					baseChecks,
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcg1.guard_point_params.guard_enabled", "false"),
				),
			},
			// Step 3: Add a second guard path.
			{
				Config: cteClientGroupGPConfig(policyName, cgName,
					cteCGGuardPoint("/tmp/testpathcg1", "\n        guard_enabled    = false")+"\n    "+cteCGGuardPoint("/tmp/testpathcg2", "")),
				Check: checkStep(t, "clientgroup_guardpoint: add second path", baseChecks),
			},
			// Step 4: Remove the first guard path (exercises unguard).
			{
				Config: cteClientGroupGPConfig(policyName, cgName, cteCGGuardPoint("/tmp/testpathcg2", "")),
				Check:  checkStep(t, "clientgroup_guardpoint: remove first path", baseChecks),
			},
			// Import: passthrough on client_group_id.
			{
				ResourceName:      cteClientGroupGPName,
				ImportState:       true,
				ImportStateIdFunc: cteAttrImportID(cteClientGroupGPName, "client_group_id"),
				ImportStateCheck:  importStateCheckAttrsSet("client_group_id"),
			},
		},
	})
}

// TestCTEClientGroupGuardPointResource_missingClientGroupID is the negative path:
// omitting the required client_group_id fails at plan time.
func TestCTEClientGroupGuardPointResource_missingClientGroupID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_clientgroup_guardpoint" "gp" {
  guard_points = {
    "/tmp/testpathcg1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = "00000000-0000-0000-0000-000000000000"
      }
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?i)client_group_id`),
			},
		},
	})
}

// TestCTEClientGroupGuardPointResource_drift flips guard_enabled out-of-band on
// the guard point and asserts the next plan is non-empty.
func TestCTEClientGroupGuardPointResource_drift(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "TF_CTE_Policy_CGGPDrift-" + suffix
	cgName := "TF_CTE_ClientGroup_GPDrift-" + suffix
	var cgID, gpID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientGroupGPConfig(policyName, cgName, cteCGGuardPoint("/tmp/testpathcg1", "\n        guard_enabled    = true")),
				Check: checkStep(t, "clientgroup_guardpoint drift: create",
					cteCaptureAttr(cteClientGroupGPName, "client_group_id", &cgID),
					cteCaptureAttr(cteClientGroupGPName, "guard_points./tmp/testpathcg1.id", &gpID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_CLIENT_GROUP+"/"+cgID+"/guardpoints", gpID, `{"guard_enabled":false}`)
				},
				Config:             cteClientGroupGPConfig(policyName, cgName, cteCGGuardPoint("/tmp/testpathcg1", "\n        guard_enabled    = true")),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCTEClientGroupGuardPointResource_guardPointTypeRequiresReplace verifies
// that changing guard_point_type is planned as a destroy+create rather than
// an in-place update, and that the apply then succeeds (TFIN-521).
func TestCTEClientGroupGuardPointResource_guardPointTypeRequiresReplace(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "TF_CTE_Policy_CGGPType-" + suffix
	cgName := "TF_CTE_ClientGroup_GPType-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientGroupGPConfig(policyName, cgName, cteCGGuardPoint("/tmp/testpathcgtype1", "")),
				Check: checkStep(t, "clientgroup_guardpoint requires replace: create",
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgtype1.guard_point_params.guard_point_type", "directory_auto"),
				),
			},
			{
				Config: strings.Replace(
					cteClientGroupGPConfig(policyName, cgName, cteCGGuardPoint("/tmp/testpathcgtype1", "")),
					`guard_point_type = "directory_auto"`,
					`guard_point_type = "directory_manual"`,
					1,
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(cteClientGroupGPName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "clientgroup_guardpoint requires replace: change guard_point_type",
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgtype1.guard_point_params.guard_point_type", "directory_manual"),
				),
			},
		},
	})
}

// TestCTEClientGroupGuardPointResource_policyIDRequiresReplace is the
// regression test for TFIN-632: policy_id was Required with no
// PlanModifiers at all, so changing it on an EXISTING guard_path was
// planned as a plain in-place update and only rejected at apply time by
// Update()'s manual AddError check ("Cannot change policy_id for an
// existing GuardPoint"). policy_id now carries
// modifiers.RequiresReplaceUnlessNewMapEntry(), so a genuine change to an
// existing entry's policy_id must be planned as a destroy+create replace
// (visible to the operator at plan time, not just a runtime apply
// failure), and the apply must then succeed cleanly.
func TestCTEClientGroupGuardPointResource_policyIDRequiresReplace(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "TF_CTE_ClientGroup_PolicyID-" + suffix

	config := func(policyResource string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "policy_a" {
  name        = "TF_CTE_Policy_CGPolicyIDA-%s"
  policy_type = "Standard"
  description = "Created via TF test"
  never_deny  = true
  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy" "policy_b" {
  name        = "TF_CTE_Policy_CGPolicyIDB-%s"
  policy_type = "Standard"
  description = "Created via TF test"
  never_deny  = true
  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Created via TF test"
}

resource "ciphertrust_cte_clientgroup_guardpoint" "gp" {
  client_group_id = ciphertrust_cte_client_group.cg.id
  guard_points = {
    "/tmp/testpathcgpolicyid1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = %s
      }
    }
  }
}
`, suffix, suffix, cgName, policyResource)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with policy_a.
			{
				Config: config("ciphertrust_cte_policy.policy_a.id"),
				Check: checkStep(t, "clientgroup_guardpoint policy_id requires replace: create",
					resource.TestCheckResourceAttrPair(cteClientGroupGPName, "guard_points./tmp/testpathcgpolicyid1.guard_point_params.policy_id", "ciphertrust_cte_policy.policy_a", "id"),
				),
			},
			// Step 2: change policy_id to policy_b on the SAME (existing)
			// guard_path. Must plan as destroy+create, not a plain update,
			// and the apply must succeed (no more runtime AddError).
			{
				Config: config("ciphertrust_cte_policy.policy_b.id"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(cteClientGroupGPName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "clientgroup_guardpoint policy_id requires replace: change policy_id",
					resource.TestCheckResourceAttrPair(cteClientGroupGPName, "guard_points./tmp/testpathcgpolicyid1.guard_point_params.policy_id", "ciphertrust_cte_policy.policy_b", "id"),
				),
			},
		},
	})
}

// TestCTEClientGroupGuardPointResource_noOpFieldsRequireReplace is the
// regression test for TFIN-633: automount_enabled, intelligent_protection,
// and disk_name (representative of the 10 affected fields -- both Bool and
// String -- see resource_cte_clientgroup_guardpoints.go's schema) had NO
// PlanModifiers and NO runtime check at all. CM silently no-ops an update
// to these fields via PATCH, so apply used to report success while state
// permanently diverged from CM with no way to self-correct (confirmed live
// against CM: the PATCH payload sent by UpdateCTEGuardPointJSON never
// included these fields at all). They now carry
// modifiers.BoolRequiresReplaceUnlessNewMapEntry() /
// modifiers.RequiresReplaceUnlessNewMapEntry(), so a genuine change to an
// EXISTING entry's value is planned as a destroy+create replace (which
// actually applies the new value, since Create() sends the full field set)
// instead of a silently no-op'd in-place update.
func TestCTEClientGroupGuardPointResource_noOpFieldsRequireReplace(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "TF_CTE_Policy_CGNoOp-" + suffix
	cgName := "TF_CTE_ClientGroup_NoOp-" + suffix

	gpBlock := func(automount, intelligentProtection, diskName string) string {
		return fmt.Sprintf(`"/tmp/testpathcgnoop1" = {
      guard_point_params = {
        guard_point_type       = "directory_auto"
        policy_id              = ciphertrust_cte_policy.policy.id
        automount_enabled      = %s
        intelligent_protection = %s
        disk_name              = %q
      }
    }`, automount, intelligentProtection, diskName)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with all 3 representative fields false/empty.
			{
				Config: cteClientGroupGPConfig(policyName, cgName, gpBlock("false", "false", "diskA")),
				Check: checkStep(t, "clientgroup_guardpoint no-op fields require replace: create",
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgnoop1.guard_point_params.automount_enabled", "false"),
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgnoop1.guard_point_params.intelligent_protection", "false"),
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgnoop1.guard_point_params.disk_name", "diskA"),
				),
			},
			// Step 2: flip all 3 on the SAME (existing) guard_path. Must
			// plan as destroy+create, not a plain in-place update that CM
			// would silently no-op.
			{
				Config: cteClientGroupGPConfig(policyName, cgName, gpBlock("true", "true", "diskB")),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(cteClientGroupGPName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "clientgroup_guardpoint no-op fields require replace: change fields",
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgnoop1.guard_point_params.automount_enabled", "true"),
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgnoop1.guard_point_params.intelligent_protection", "true"),
					resource.TestCheckResourceAttr(cteClientGroupGPName, "guard_points./tmp/testpathcgnoop1.guard_point_params.disk_name", "diskB"),
				),
			},
		},
	})
}
