package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEClientGroupGuardPoint(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create Policy + ClientGroup + GuardPoint
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "TF_CTE_Policy_CG_Test"
  policy_type = "Standard"
  description = "Created via TF test"
  never_deny  = true

  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = "TF_CTE_ClientGroup_Test"
  cluster_type = "NON-CLUSTER"
  description  = "Created via TF test"
}

resource "ciphertrust_cte_clientgroup_guardpoint" "gp" {
  client_group_id = ciphertrust_cte_client_group.cg.id

  guard_points = {
    "/tmp/testpathcg1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "client_group_id"),
				),
			},

			// Step 2: Update GuardPoint (disable guard_enabled)
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "TF_CTE_Policy_CG_Test"
  policy_type = "Standard"
  description = "Created via TF test"
  never_deny  = true

  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = "TF_CTE_ClientGroup_Test"
  cluster_type = "NON-CLUSTER"
  description  = "Created via TF test"
}

resource "ciphertrust_cte_clientgroup_guardpoint" "gp" {
  client_group_id = ciphertrust_cte_client_group.cg.id

  guard_points = {
    "/tmp/testpathcg1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
        guard_enabled    = false
      }
    }
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "client_group_id"),
				),
			},

			// Step 3: Add a second guard path
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "TF_CTE_Policy_CG_Test"
  policy_type = "Standard"
  description = "Created via TF test"
  never_deny  = true

  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = "TF_CTE_ClientGroup_Test"
  cluster_type = "NON-CLUSTER"
  description  = "Created via TF test"
}

resource "ciphertrust_cte_clientgroup_guardpoint" "gp" {
  client_group_id = ciphertrust_cte_client_group.cg.id

  guard_points = {
    "/tmp/testpathcg1" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
        guard_enabled    = false
      }
    }
    "/tmp/testpathcg2" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "client_group_id"),
				),
			},

			// Step 4: Remove first guard path (tests unguard path in Update)
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "policy" {
  name        = "TF_CTE_Policy_CG_Test"
  policy_type = "Standard"
  description = "Created via TF test"
  never_deny  = true

  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = "TF_CTE_ClientGroup_Test"
  cluster_type = "NON-CLUSTER"
  description  = "Created via TF test"
}

resource "ciphertrust_cte_clientgroup_guardpoint" "gp" {
  client_group_id = ciphertrust_cte_client_group.cg.id

  guard_points = {
    "/tmp/testpathcg2" = {
      guard_point_params = {
        guard_point_type = "directory_auto"
        policy_id        = ciphertrust_cte_policy.policy.id
      }
    }
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_clientgroup_guardpoint.gp", "client_group_id"),
				),
			},

			// Delete testing automatically occurs in TestCase
		},
	})
}
