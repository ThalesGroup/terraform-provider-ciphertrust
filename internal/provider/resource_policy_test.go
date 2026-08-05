package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceCMPolicy(t *testing.T) {
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

func Test_CM_ResourceCMPolicyEffectDefault(t *testing.T) {
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
		op     = "equals"
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

func Test_CM_AccCMPolicy_drift(t *testing.T) {
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
						"actions":   []string{"CreateKey", "DeleteKey"},
						"resources": []string{"kylo:*:vault:keys:*", "kylo:*:vault:keys:other"},
						"conditions": []map[string]interface{}{
							{"op": "equals", "path": "context.resource.alg", "values": []string{"rsa"}},
						},
					})
					_, _ = client.UpdateDataV2(context.Background(), policyID, common.URL_CM_POLICIES, modifiedPayload)
				},
				// All policy fields (actions, resources, conditions) now carry ImmutableList/
				// ImmutableString modifiers (TFIN-515). When CM changes them out-of-band the
				// refresh reads new server values into state; the subsequent plan sees config !=
				// refreshed-state on an immutable field and emits AddError rather than a plain
				// diff. ExpectError reflects the actual post-TFIN-515 behaviour.
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCipherTrust_Policy_ImmutableName verifies that changing the name on a
// ciphertrust_policies resource produces a plan-time error from ImmutableString.
func Test_CM_AccCipherTrust_Policy_ImmutableName(t *testing.T) {
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

// Test_CM_AccCMPolicy_ImmutableName verifies that ImmutableString() rejects an in-place
// name change at plan time.
func Test_CM_AccCMPolicy_ImmutableName(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "immut" {
  name    = "tf-test-policy-immut"
  actions = ["CreateKey"]
  effect  = "allow"
}
`,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_policies.immut", "name", "tf-test-policy-immut"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "immut" {
  name    = "tf-test-policy-immut-changed"
  actions = ["CreateKey"]
  effect  = "allow"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_AttributeDrift verifies that Read() surfaces drift when effect is
// changed out-of-band.
func Test_CM_AccCMPolicy_AttributeDrift(t *testing.T) {
	RequireCM(t)
	var policyID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "drift" {
  name    = "tf-test-policy-drift"
  actions = ["CreateKey"]
  effect  = "allow"
}
`,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_policies.drift", "effect", "allow"),
					func(s *terraform.State) error {
						rs := s.RootModule().Resources["ciphertrust_policies.drift"]
						if rs == nil {
							return fmt.Errorf("ciphertrust_policies.drift not found in state")
						}
						policyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, err := client.UpdateDataV2(context.Background(), policyID, common.URL_CM_POLICIES, []byte(`{"effect":"deny"}`))
					if err != nil {
						_ = err
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMPolicy_OutOfBandDeletion verifies that Read() returns AddError + preserves state on 404 (PR #476 behavior).
func Test_CM_AccCMPolicy_OutOfBandDeletion(t *testing.T) {
	RequireCM(t)
	var policyID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "oob" {
  name    = "tf-test-policy-oob"
  actions = ["CreateKey"]
  effect  = "allow"
}
`,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_policies.oob", "name", "tf-test-policy-oob"),
					func(s *terraform.State) error {
						rs := s.RootModule().Resources["ciphertrust_policies.oob"]
						if rs == nil {
							return fmt.Errorf("ciphertrust_policies.oob not found in state")
						}
						policyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), common.URL_CM_POLICIES+"/"+policyID)
				},
				Config: providerConfig + `
resource "ciphertrust_policies" "oob" {
  name    = "tf-test-policy-oob"
  actions = ["CreateKey"]
  effect  = "allow"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)not found on ciphertrust manager`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_Idempotency verifies no spurious plan diff after apply from
// Computed fields (id, uri, account, created_at).
func Test_CM_AccCMPolicy_Idempotency(t *testing.T) {
	RequireCM(t)

	config := providerConfig + `
resource "ciphertrust_policies" "idem" {
  name    = "tf-test-policy-idem"
  actions = ["CreateKey"]
  effect  = "allow"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttrSet("ciphertrust_policies.idem", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_policies.idem", "uri"),
					resource.TestCheckResourceAttrSet("ciphertrust_policies.idem", "account"),
					resource.TestCheckResourceAttrSet("ciphertrust_policies.idem", "created_at"),
				),
			},
			{
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMPolicy_ImmutableActions verifies that changing actions after creation produces
// a plan-time immutable error from ImmutableList.
func Test_CM_AccCMPolicy_ImmutableActions(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["DeleteKey"]
  effect  = "deny"
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "actions.0", "DeleteKey"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["ReadKey"]
  effect  = "deny"
}
`, policyName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_ImmutableAllow verifies that changing allow after creation produces
// a plan-time immutable error from ImmutableBool.
func Test_CM_AccCMPolicy_ImmutableAllow(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name   = %q
  effect = "deny"
  allow  = false
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "allow", "false"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name   = %q
  effect = "deny"
  allow  = true
}
`, policyName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_ImmutableEffect verifies that changing effect after creation produces
// a plan-time immutable error from ImmutableString.
func Test_CM_AccCMPolicy_ImmutableEffect(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name   = %q
  effect = "deny"
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "effect", "deny"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name   = %q
  effect = "allow"
}
`, policyName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_ImmutableIncludeDescendantAccounts verifies that adding
// include_descendant_accounts after creation produces a plan-time immutable error.
// Step 1 omits include_descendant_accounts (null state); step 2 attempts to set it,
// triggering the ImmutableBool error since the field cannot be changed after creation.
func Test_CM_AccCMPolicy_ImmutableIncludeDescendantAccounts(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name   = %q
  effect = "deny"
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name                        = %q
  effect                      = "deny"
  include_descendant_accounts = true
}
`, policyName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_EffectValidator verifies that an invalid effect value produces
// a plan-time validation error before any CM API call.
func Test_CM_AccCMPolicy_EffectValidator(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name   = %q
  effect = "invalid_effect_value"
}
`, policyName),
				ExpectError: regexp.MustCompile("Invalid Attribute Value Match"),
			},
		},
	})
}

// Test_CM_AccCMPolicy_ConditionsOpValidator verifies that an invalid op value in a
// conditions block produces a plan-time validation error before any CM API call.
func Test_CM_AccCMPolicy_ConditionsOpValidator(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name = %q
  conditions = [{
    op     = "bogus_op"
    path   = "some/key"
    values = ["some_value"]
  }]
}
`, policyName),
				ExpectError: regexp.MustCompile("Invalid Attribute Value Match"),
			},
		},
	})
}

// Test_CM_AccCMPolicy_ImmutableResources verifies that changing resources after
// creation produces a plan-time immutable error (TFIN-515 Bug 1).
func Test_CM_AccCMPolicy_ImmutableResources(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name      = %q
  effect    = "deny"
  actions   = ["ReadKey"]
  resources = ["kylo:*:vault:keys:original"]
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "resources.0", "kylo:*:vault:keys:original"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name      = %q
  effect    = "deny"
  actions   = ["ReadKey"]
  resources = ["kylo:*:vault:keys:changed"]
}
`, policyName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_ImmutableConditions verifies that changing conditions after
// creation produces a plan-time immutable error (TFIN-515 Bug 2).
func Test_CM_AccCMPolicy_ImmutableConditions(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  effect  = "deny"
  actions = ["ReadKey"]
  conditions = [{
    op     = "equals"
    path   = "subject/username"
    values = ["alice"]
  }]
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "conditions.0.op", "equals"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  effect  = "deny"
  actions = ["ReadKey"]
  conditions = [{
    op     = "equals"
    path   = "subject/username"
    values = ["bob"]
  }]
}
`, policyName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPolicy_IncludeDescendantAccountsNoCreateCrash verifies that creating
// a policy with include_descendant_accounts = true does not crash with
// "provider produced inconsistent result after apply" (TFIN-515 Bug 3).
// CM does not echo this field in POST or GET responses; the provider must preserve
// the configured value rather than nulling it out.
func Test_CM_AccCMPolicy_IncludeDescendantAccountsNoCreateCrash(t *testing.T) {
	RequireCM(t)
	policyName := "tftest-policy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name                        = %q
  effect                      = "deny"
  actions                     = ["ReadKey"]
  include_descendant_accounts = true
}
`, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policies.test", "include_descendant_accounts", "true"),
				),
			},
			{
				// Idempotency: second plan must be empty — no drift from missing field in CM response.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name                        = %q
  effect                      = "deny"
  actions                     = ["ReadKey"]
  include_descendant_accounts = true
}
`, policyName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
