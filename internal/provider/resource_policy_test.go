package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMPolicy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  	name    =   "policyReadKeyOnly"
    actions =   ["ReadKey"]
    allow   =   true
    effect  =   "allow"
    conditions = [{
        path   = "context.resource.alg"
        op     = "equals"
        values = ["aes","rsa"]
    }]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.policy", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestResourceCMPolicyEffectDefault(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy_no_effect" {
	name    =   "policyWithoutEffect"
	actions =   ["DeleteKey"]
	allow   =   false
	resources = ["kylo:*:vault:keys:*"]
	conditions = [{
		path   = "context.resource.meta.cte"
		op     = "empty"
		negate = true
	}]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.policy_no_effect", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.policy_no_effect", "effect", "deny"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccCMPolicy_DriftConditions(t *testing.T) {
	policyName := "tf-test-drift-" + uuid.New().String()[:8]
	resourceAddr := "ciphertrust_policies.drift_policy"
	var policyID string

	policyConfig := func() string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "drift_policy" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
  include_descendant_accounts = true
  conditions = [{
    path   = "context.resource.alg"
    op     = "equals"
    values = ["aes", "rsa"]
  }]
}
`, policyName)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: policyConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceAddr, "id"),
					resource.TestCheckResourceAttr(resourceAddr, "include_descendant_accounts", "true"),
					resource.TestCheckResourceAttr(resourceAddr, "conditions.#", "1"),
					resource.TestCheckResourceAttr(resourceAddr, "conditions.0.path", "context.resource.alg"),
					resource.TestCheckResourceAttr(resourceAddr, "conditions.0.op", "equals"),
					testAccListResourceAttributes(resourceAddr),
					func(s *terraform.State) error {
						rs := s.RootModule().Resources[resourceAddr]
						if rs == nil {
							return fmt.Errorf("resource %s not found in state", resourceAddr)
						}
						policyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// No false drift on a subsequent plan — Read() must round-trip all attributes cleanly.
				Config:             policyConfig(),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Out-of-band mutation via the CM API; expect Terraform to detect the diff.
				PreConfig: func() {
					if policyID == "" {
						t.Skip("policy ID not captured from state, skipping drift step")
					}
					client, ok := createCMClient()
					if !ok {
						t.Skip("skipping out-of-band drift check: CipherTrust credentials not available")
					}
					patch := map[string]interface{}{
						"conditions": []map[string]interface{}{
							{"path": "context.resource.alg", "op": "equals", "values": []string{"aes"}},
						},
					}
					patchJSON, _ := json.Marshal(patch)
					_, err := client.UpdateDataV2(context.Background(), policyID, common.URL_CM_POLICIES, patchJSON)
					if err != nil {
						t.Logf("out-of-band mutation warning: %v", err)
					}
				},
				Config:             policyConfig(),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCMPolicy_Update(t *testing.T) {
	policyName := "tf-test-upd-" + uuid.New().String()[:8]
	resourceAddr := "ciphertrust_policies.update_policy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "update_policy" {
  name    = %q
  actions = ["ReadKey"]
  allow   = false
  effect  = "deny"
  include_descendant_accounts = false
  conditions = [{
    path   = "context.resource.alg"
    op     = "equals"
    values = ["aes"]
  }]
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceAddr, "id"),
					resource.TestCheckResourceAttr(resourceAddr, "effect", "deny"),
					resource.TestCheckResourceAttr(resourceAddr, "include_descendant_accounts", "false"),
					resource.TestCheckResourceAttr(resourceAddr, "conditions.0.values.0", "aes"),
					resource.TestCheckResourceAttr(resourceAddr, "conditions.0.values.#", "1"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "update_policy" {
  name    = %q
  actions = ["ReadKey", "CreateKey"]
  allow   = true
  effect  = "allow"
  include_descendant_accounts = true
  conditions = [{
    path   = "context.resource.alg"
    op     = "equals"
    values = ["aes", "rsa"]
  }]
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddr, "effect", "allow"),
					resource.TestCheckResourceAttr(resourceAddr, "include_descendant_accounts", "true"),
					resource.TestCheckResourceAttr(resourceAddr, "conditions.0.values.#", "2"),
					resource.TestCheckResourceAttr(resourceAddr, "conditions.0.values.1", "rsa"),
					resource.TestCheckResourceAttr(resourceAddr, "actions.#", "2"),
				),
			},
			{
				// Verify no drift after the update.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "update_policy" {
  name    = %q
  actions = ["ReadKey", "CreateKey"]
  allow   = true
  effect  = "allow"
  include_descendant_accounts = true
  conditions = [{
    path   = "context.resource.alg"
    op     = "equals"
    values = ["aes", "rsa"]
  }]
}
`, policyName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
