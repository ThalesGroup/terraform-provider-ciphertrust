package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEClientGuardPoint(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "TF_CTE_Policy_Test-" + suffix
	clientName := "TF_CTE_Client_Test-" + suffix

	// baseConfig returns the shared policy + client block used by every step.
	baseConfig := func(extraGP string) string {
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
  labels = {
    color = "blue"
  }
}

resource "ciphertrust_cte_client_guardpoint" "gp" {
  client_id = ciphertrust_cte_client.client.id

  guard_points = {
    %s
  }
}
`, policyName, clientName, extraGP)
	}

	gpChecks := resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet("ciphertrust_cte_client_guardpoint.gp", "id"),
		resource.TestCheckResourceAttrSet("ciphertrust_cte_client_guardpoint.gp", "client_id"),
	)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create Policy + Client + GuardPoint
			{
				Config: baseConfig(`"/tmp/testpath1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }`),
				Check: gpChecks,
			},

			// Step 2: Update GuardPoint (disable guard_enabled)
			{
				Config: baseConfig(`"/tmp/testpath1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
        guard_enabled    = false
      }
    }`),
				Check: gpChecks,
			},

			// Step 3: Add a second guard path
			{
				Config: baseConfig(`"/tmp/testpath1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
        guard_enabled    = false
      }
    }
    "/tmp/testpath2" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }`),
				Check: gpChecks,
			},

			// Step 4: Remove first guard path (tests unguard path in Update)
			{
				Config: baseConfig(`"/tmp/testpath2" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }`),
				Check: gpChecks,
			},

			// Delete testing automatically occurs in TestCase
		},
	})
}
