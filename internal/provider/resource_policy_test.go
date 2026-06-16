package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

func TestAccCMPolicyConditionsDrift(t *testing.T) {
	RequireCM(t)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testConditionsDriftPolicy"
  actions = ["ReadKey"]
  allow  = true
  effect = "allow"
  conditions = [{
    op     = "equals"
    path   = "context.resource.alg"
    values = ["aes"]
  }]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.policy", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.policy", "conditions.0.op", "equals"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_policies.policy"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload := []byte(`{"conditions":[{"op":"equals","path":"context.resource.alg","values":["rsa"]}]}`)
					_, _ = client.UpdateDataV2(context.Background(), capturedID, common.URL_CM_POLICIES, patchPayload)
				},
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testConditionsDriftPolicy"
  actions = ["ReadKey"]
  allow  = true
  effect = "allow"
  conditions = [{
    op     = "equals"
    path   = "context.resource.alg"
    values = ["aes"]
  }]
}
`,
			},
		},
	})
}

func TestAccCMPolicyConditionsUpdate(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testConditionsUpdatePolicy"
  actions = ["ReadKey"]
  allow  = true
  effect = "allow"
  conditions = [{
    op     = "equals"
    path   = "context.resource.alg"
    values = ["aes"]
  }]
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policies.policy", "conditions.0.values.0", "aes"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testConditionsUpdatePolicy"
  actions = ["ReadKey"]
  allow  = true
  effect = "allow"
  conditions = [{
    op     = "equals"
    path   = "context.resource.alg"
    values = ["rsa"]
  }]
}
`,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_policies.policy", "conditions.0.values.0", "rsa"),
				),
			},
		},
	})
}

func TestAccCMPolicyIncludeDescendantAccountsUpdate(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name    = "testIncludeDescPolicy"
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_policies.policy", "id"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name                        = "testIncludeDescPolicy"
  actions                     = ["ReadKey"]
  allow                       = true
  effect                      = "allow"
  include_descendant_accounts = true
}
`,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_policies.policy", "include_descendant_accounts", "true"),
				),
			},
		},
	})
}

func TestAccCMPolicyAllowConditionalHydration(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name    = "testAllowPolicy"
  actions = ["ReadKey"]
  effect  = "allow"
  allow   = true
}
`,
				Check: checkStep(t, "allow=true",
					resource.TestCheckResourceAttr("ciphertrust_policies.policy", "allow", "true"),
				),
			},
			{
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name    = "testAllowPolicy"
  actions = ["ReadKey"]
  effect  = "allow"
  allow   = true
}
`,
			},
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
