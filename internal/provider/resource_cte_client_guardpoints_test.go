package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

const cteClientGPName = "ciphertrust_cte_client_guardpoint.gp"

// cteClientGPConfig renders a policy + client + client guardpoint. extraGP is the
// guard_points map body, letting each step vary the guard paths / params.
func cteClientGPConfig(policyName, clientName, extraGP string) string {
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

resource "ciphertrust_cte_client" "client" {
  name                     = %q
  client_type              = "FS"
  registration_allowed     = true
  communication_enabled    = true
  description              = "Created via TF test"
  password_creation_method = "GENERATE"
}

resource "ciphertrust_cte_client_guardpoint" "gp" {
  client_id = ciphertrust_cte_client.client.id
  guard_points = {
    %s
  }
}
`, policyName, clientName, extraGP)
}

func cteClientGP1(guardEnabled string) string {
	return `"/tmp/testpath1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id` + guardEnabled + `
      }
    }`
}

func TestCTEClientGuardPointResource(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "TF_CTE_Policy_Test-" + suffix
	clientName := "TF_CTE_Client_Test-" + suffix

	baseChecks := resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(cteClientGPName, "id"),
		resource.TestCheckResourceAttrSet(cteClientGPName, "client_id"),
	)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with guard_enabled = true. Guard points apply
			// asynchronously, so wait for them to settle before asserting.
			{
				Config: cteClientGPConfig(policyName, clientName, cteClientGP1("\n        guard_enabled    = true")),
				Check: checkStep(t, "client_guardpoint: create",
					baseChecks,
					cteWaitGuardPointsSettled(cteClientGPName, "client_id", 90*time.Second),
					resource.TestCheckResourceAttr(cteClientGPName, "guard_points./tmp/testpath1.guard_point_params.guard_enabled", "true"),
				),
			},
			// Step 2: Update guard_enabled = false and read it back.
			{
				Config: cteClientGPConfig(policyName, clientName, cteClientGP1("\n        guard_enabled    = false")),
				Check: checkStep(t, "client_guardpoint: update guard_enabled",
					baseChecks,
					cteWaitGuardPointsSettled(cteClientGPName, "client_id", 90*time.Second),
					resource.TestCheckResourceAttr(cteClientGPName, "guard_points./tmp/testpath1.guard_point_params.guard_enabled", "false"),
				),
			},
			// Step 3: Add a second guard path.
			{
				Config: cteClientGPConfig(policyName, clientName, cteClientGP1("\n        guard_enabled    = false")+`
    "/tmp/testpath2" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }`),
				Check: checkStep(t, "client_guardpoint: add second path", baseChecks),
			},
			// Step 4: Remove the first guard path (exercises the unguard path).
			{
				Config: cteClientGPConfig(policyName, clientName, `"/tmp/testpath2" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }`),
				Check: checkStep(t, "client_guardpoint: remove first path", baseChecks),
			},
			// Import: passthrough on client_id (not the resource's composite id).
			{
				ResourceName:      cteClientGPName,
				ImportState:       true,
				ImportStateIdFunc: cteAttrImportID(cteClientGPName, "client_id"),
				ImportStateCheck:  importStateCheckAttrsSet("client_id"),
			},
		},
	})
}

// TestCTEClientGuardPointResource_drift is the drift-detection test for the
// "guardpoint" category: flip guard_enabled out-of-band and assert a non-empty
// plan. The guard point id and client id are captured after the create settles.
func TestCTEClientGuardPointResource_drift(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "TF_CTE_Policy_Drift-" + suffix
	clientName := "TF_CTE_Client_Drift-" + suffix
	var clientID, gpID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientGPConfig(policyName, clientName, cteClientGP1("\n        guard_enabled    = true")),
				Check: checkStep(t, "client_guardpoint drift: create",
					cteWaitGuardPointsSettled(cteClientGPName, "client_id", 90*time.Second),
					cteCaptureAttr(cteClientGPName, "client_id", &clientID),
					cteCaptureAttr(cteClientGPName, "guard_points./tmp/testpath1.id", &gpID),
				),
			},
			{
				PreConfig: func() {
					// Disable the guard point out-of-band on the live client.
					cteOutOfBandPatch(common.URL_CTE_CLIENT+"/"+clientID+"/guardpoints", gpID, `{"guard_enabled":false}`)
				},
				Config:             cteClientGPConfig(policyName, clientName, cteClientGP1("\n        guard_enabled    = true")),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCTEClientGuardPointResource_guardPointTypeReplaceScope is the regression
// test for TFIN-634: guard_point_type's plan modifier must only force a
// whole-resource replace for a genuine change to an EXISTING, already-converged
// guard point -- never for the mere addition of a brand-new guard_path. Before
// the fix, adding ANY new guard_path forced a destroy-then-create replace of the
// entire resource (even though no existing guard point's type changed), so a
// failed Create() during that replace destroyed every existing guard point with
// no rollback. Step 2 asserts the addition is a plain in-place update; step 3
// asserts that a genuine type change on an existing entry still safely replaces.
func TestCTEClientGuardPointResource_guardPointTypeReplaceScope(t *testing.T) {
	suffix := uuid.New().String()[:8]
	// Lowercase-only names: this live CM environment normalizes CTE client
	// names to lowercase server-side, which collides with the (separately
	// already-fixed, out-of-scope-here) TFIN-461 immutable-name plan modifier
	// on ciphertrust_cte_client.name if the configured name has any uppercase
	// characters -- unrelated to this test's guard_point_type replace-scope
	// assertions, so side-stepped here by simply not using uppercase letters.
	policyName := "tf-cte-policy-gptypescope-" + suffix
	clientName := "tf-cte-client-gptypescope-" + suffix

	newPathBlock := `
    "/tmp/testpath_new" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with a single guard point.
			{
				Config: cteClientGPConfig(policyName, clientName, cteClientGP1("")),
				Check: checkStep(t, "client_guardpoint replace-scope: create",
					cteWaitGuardPointsSettled(cteClientGPName, "client_id", 90*time.Second),
					resource.TestCheckResourceAttr(cteClientGPName, "guard_points./tmp/testpath1.guard_point_params.guard_point_type", "directory_auto"),
				),
			},
			// Step 2: add a brand-new guard point. This must plan as a plain
			// in-place update, never a destroy-before-create replace -- the
			// existing guard point must not be touched just because a new,
			// unrelated guard_path was added.
			{
				Config: cteClientGPConfig(policyName, clientName, cteClientGP1("")+newPathBlock),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(cteClientGPName, plancheck.ResourceActionUpdate),
					},
				},
				Check: checkStep(t, "client_guardpoint replace-scope: add new path is in-place",
					resource.TestCheckResourceAttr(cteClientGPName, "guard_points./tmp/testpath1.guard_point_params.guard_point_type", "directory_auto"),
					resource.TestCheckResourceAttr(cteClientGPName, "guard_points./tmp/testpath_new.guard_point_params.guard_point_type", "directory_auto"),
				),
			},
			// Step 3: change the EXISTING guard point's (/tmp/testpath1) type.
			// This safety behavior must be preserved: it still forces a
			// destroy-before-create replace of the whole resource. strings.Replace
			// with count=1 targets the first "directory_auto" occurrence, which is
			// /tmp/testpath1's (it appears before /tmp/testpath_new in the config).
			{
				Config: strings.Replace(
					cteClientGPConfig(policyName, clientName, cteClientGP1("")+newPathBlock),
					`guard_point_type = "directory_auto"`,
					`guard_point_type = "directory_manual"`,
					1,
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(cteClientGPName, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "client_guardpoint replace-scope: existing type change still replaces",
					resource.TestCheckResourceAttr(cteClientGPName, "guard_points./tmp/testpath1.guard_point_params.guard_point_type", "directory_manual"),
				),
			},
		},
	})
}

// TestCTEClientGuardPointResource_missingClientID is the negative path: omitting
// the required client_id fails at plan time.
func TestCTEClientGuardPointResource_missingClientID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_client_guardpoint" "gp" {
  guard_points = {
    "/tmp/testpath1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = "00000000-0000-0000-0000-000000000000"
      }
    }
  }
}
`,
				ExpectError: regexp.MustCompile(`(?i)client_id`),
			},
		},
	})
}
