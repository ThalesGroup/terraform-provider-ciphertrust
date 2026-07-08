package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMPolicy(t *testing.T) {
	RequireCM(t)
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
	RequireCM(t)
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

func TestAccCMPolicy_drift(t *testing.T) {
	RequireCM(t)
	var policyID string

	initialConfig := providerConfig + `
resource "ciphertrust_policies" "test" {
  name    = "tf-acc-drift-policy"
  effect  = "allow"
  allow   = true
  actions = ["CreateKey"]
  resources = ["kylo:*:vault:keys:*"]
  conditions = [{
    op     = "equals"
    path   = "context.resource.alg"
    values = ["aes"]
  }]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "name", "tf-acc-drift-policy"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "allow", "true"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "conditions.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "conditions.0.op", "equals"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "actions.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "resources.#", "1"),
					func(s *terraform.State) error {
						policyID = s.RootModule().Resources["ciphertrust_policies.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					modifiedPayload, _ := json.Marshal(map[string]interface{}{
						"actions": []string{"CreateKey", "DeleteKey"},
						"resources": []string{"kylo:*:vault:keys:*", "kylo:*:vault:keys:other"},
						"conditions": []map[string]interface{}{
							{"op": "equals", "path": "context.resource.alg", "values": []string{"rsa"}},
						},
					})
					_, _ = client.UpdateDataV2(context.Background(), policyID, common.URL_CM_POLICIES, modifiedPayload)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrust_Policy_ImmutableName verifies that changing the name on a
// ciphertrust_policies resource produces a plan-time error from ImmutableString.
func TestAccCipherTrust_Policy_ImmutableName(t *testing.T) {
	RequireCM(t)

	initialConfig := providerConfig + `
resource "ciphertrust_policies" "test" {
  name    = "tf-acc-immut-name-policy"
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "name", "tf-acc-immut-name-policy"),
				),
			},
			// Changing name must produce an immutable error at plan time.
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "test" {
  name    = "tf-acc-immut-name-policy-changed"
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

func TestAccCMPolicy_update(t *testing.T) {
	RequireCM(t)
	var policyID string

	initialConfig := providerConfig + `
resource "ciphertrust_policies" "test" {
  name    = "tf-acc-update-policy"
  effect  = "allow"
  actions = ["ReadKey"]
  conditions = [{
    op     = "equals"
    path   = "context.resource.alg"
    values = ["aes"]
  }]
}
`

	updatedConfig := providerConfig + `
resource "ciphertrust_policies" "test" {
  name    = "tf-acc-update-policy"
  effect  = "allow"
  actions = ["ReadKey"]
  conditions = [{
    op     = "equals"
    path   = "context.resource.alg"
    values = ["aes"]
  }, {
    op     = "equals"
    path   = "context.resource.alg"
    values = ["rsa"]
  }]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "effect", "allow"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "conditions.#", "1"),
					func(s *terraform.State) error {
						policyID = s.RootModule().Resources["ciphertrust_policies.test"].Primary.ID
						return nil
					},
				),
			},
			{
				Config: updatedConfig,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "conditions.#", "2"),
					func(s *terraform.State) error {
						updatedID := s.RootModule().Resources["ciphertrust_policies.test"].Primary.ID
						if updatedID != policyID {
							return fmt.Errorf("expected no destroy+recreate: ID changed from %s to %s", policyID, updatedID)
						}
						return nil
					},
				),
			},
			{
				Config:             updatedConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
