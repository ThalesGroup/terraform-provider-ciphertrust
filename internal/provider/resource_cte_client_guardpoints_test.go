package provider

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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

func TestResourceCTEClientGuardPoint(t *testing.T) {
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

// TestResourceCTEClientGuardPoint_drift is the drift-detection test for the
// "guardpoint" category: flip guard_enabled out-of-band and assert a non-empty
// plan. The guard point id and client id are captured after the create settles.
func TestResourceCTEClientGuardPoint_drift(t *testing.T) {
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

// TestResourceCTEClientGuardPoint_missingClientID is the negative path: omitting
// the required client_id fails at plan time.
func TestResourceCTEClientGuardPoint_missingClientID(t *testing.T) {
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
