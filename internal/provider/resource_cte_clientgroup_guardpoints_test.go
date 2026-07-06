package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
