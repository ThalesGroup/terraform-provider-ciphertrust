package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceCMPolicyAttachment(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  	name    =   "mypolicy"
    actions =   ["ReadKey"]
    allow   =   true
    effect  =   "allow"
    conditions = [{
        path   = "context.resource.alg"
        op     = "equals"
        values = ["aes","rsa"]
    }]
}

resource "ciphertrust_policy_attachments" "policy_attachment" {
  	policy = "mypolicy"
	principal_selector = {
		acct = "pers-jsmith"
		user = "apitestuser"
	}
	depends_on = [ciphertrust_policies.policy]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.policy_attachment", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// Test_CM_CMPolicyAttachmentOutOfBandDeletion verifies that when a policy attachment is
// deleted directly on CipherTrust Manager (out-of-band), the next terraform refresh
// removes it from state gracefully and triggers a plan to recreate it.
func Test_CM_CMPolicyAttachmentOutOfBandDeletion(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-oob-policy-%d", time.Now().Unix())
	var capturedID string

	policyConfig := fmt.Sprintf(`
resource "ciphertrust_policies" "oob_policy" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "oob_attachment" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.oob_policy]
}
`, policyName, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the attachment, capture its ID.
			{
				Config: providerConfig + policyConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.oob_attachment", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_policy_attachments.oob_attachment"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: Delete out-of-band then refresh. Read() gets 404 → RemoveResource.
			// Resource is removed from state; plan shows recreation → non-empty plan.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM not configured")
					}
					endpoint := common.URL_CM_POLICY_ATTACHMENTS + "/" + capturedID
					_, _ = client.DeleteByURL(context.Background(), capturedID, endpoint)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMPolicyAttachment_ComputedActionsResources verifies that actions/resources on
// ciphertrust_policy_attachments are derived from the linked policy (not independently
// settable), and that re-applying the same config produces no drift.
func Test_CM_AccCMPolicyAttachment_ComputedActionsResources(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-acc-attach-computed-pol-%d", time.Now().Unix())

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name      = %q
  actions   = ["CreateKey"]
  resources = ["kylo://"]
  allow     = true
  effect    = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.test", "actions.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.test", "actions.0", "CreateKey"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.test", "resources.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.test", "resources.0", "kylo://"),
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

// Test_CM_AccCMPolicyAttachment_ActionsNotConfigurable verifies that setting actions or
// resources directly on ciphertrust_policy_attachments is rejected at plan time with a
// Read-Only Attribute error, instead of being silently discarded by CM and causing a
// "provider produced inconsistent result after apply" crash.
func Test_CM_AccCMPolicyAttachment_ActionsNotConfigurable(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-acc-attach-notcfg-pol-%d", time.Now().Unix())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["CreateKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  actions    = ["CreateKey"]
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName),
				ExpectError: regexp.MustCompile(`(?i)read-only attribute`),
			},
		},
	})
}

func Test_CM_AccCMPolicyAttachment_update(t *testing.T) {
	RequireCM(t)

	policyName := fmt.Sprintf("tf-acc-attach-upd-pol-%d", time.Now().Unix())

	initialConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["CreateKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName)

	// principal_selector is now immutable — changing it must be rejected at plan time.
	updatedConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["CreateKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser2"
  }
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.test", "principal_selector.user", "apitestuser"),
				),
			},
			// Changing principal_selector must be rejected at plan time by ImmutableMap().
			{
				Config:             updatedConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCipherTrust_PolicyAttachment_ImmutableFields verifies that changing the
// immutable policy field on a ciphertrust_policy_attachments resource produces a
// plan-time error from ImmutableString.
func Test_CM_AccCipherTrust_PolicyAttachment_ImmutableFields(t *testing.T) {
	RequireCM(t)

	policyName := fmt.Sprintf("tf-acc-attach-immf-pol-%d", time.Now().Unix())

	initialConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName)

	changedPolicyConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = "some-other-policy-immf"
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.test]
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.test", "id"),
				),
			},
			// Changing policy must produce an immutable error at plan time.
			{
				Config:             changedPolicyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_AccCMPolicyAttachment_immutablePolicy(t *testing.T) {
	RequireCM(t)

	policyName := fmt.Sprintf("tf-acc-attach-immut-pol-%d", time.Now().Unix())

	initialConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["CreateKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName)

	changedPolicyConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["CreateKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "test" {
  policy = "some-other-policy-id"
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.test]
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.test", "id"),
				),
			},
			{
				Config:             changedPolicyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CipherTrust_PolicyAttachment_ImmutableJurisdiction_NullToNonNull verifies that adding
// jurisdiction to an attachment where it was null in prior state fires the ImmutableString
// modifier at plan time after the IsNull→IsUnknown fix.
func Test_CM_CipherTrust_PolicyAttachment_ImmutableJurisdiction_NullToNonNull(t *testing.T) {
	RequireCM(t)

	policyID := os.Getenv("CM_POLICY_ID")
	principalUser := os.Getenv("CM_PRINCIPAL_USER")
	if policyID == "" || principalUser == "" {
		t.Skip("Skipping: CM_POLICY_ID and CM_PRINCIPAL_USER must be set")
	}

	step1Config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policy_attachments" "test" {
  policy             = %q
  principal_selector = { user = %q }
}
`, policyID, principalUser)

	step2Config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policy_attachments" "test" {
  policy             = %q
  principal_selector = { user = %q }
  jurisdiction       = "root"
}
`, policyID, principalUser)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: step1Config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.test", "id"),
				),
			},
			{
				Config:             step2Config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMPolicyAttachment_ResourcesNotConfigurable verifies that setting resources
// directly on ciphertrust_policy_attachments is rejected at plan time with a Read-Only
// Attribute error, same as actions.
func Test_CM_AccCMPolicyAttachment_ResourcesNotConfigurable(t *testing.T) {
	RequireCM(t)

	policyID := os.Getenv("CM_POLICY_ID")
	principalUser := os.Getenv("CM_PRINCIPAL_USER")
	if policyID == "" || principalUser == "" {
		t.Skip("Skipping: CM_POLICY_ID and CM_PRINCIPAL_USER must be set")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policy_attachments" "test_resources" {
  policy             = %q
  principal_selector = { user = %q }
  resources          = ["kylo://"]
}
`, policyID, principalUser),
				ExpectError: regexp.MustCompile(`(?i)read-only attribute`),
			},
		},
	})
}

// Test_CM_AccCMPolicyAttachment_Idempotency verifies no spurious plan diff after apply
// from Computed fields (id, uri, account, created_at).
func Test_CM_AccCMPolicyAttachment_Idempotency(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-test-attach-pol-idem-%d", time.Now().Unix())

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "idem_pol" {
  name    = %q
  actions = ["CreateKey"]
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "idem" {
  policy = ciphertrust_policies.idem_pol.id
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.idem_pol]
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.idem", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.idem", "uri"),
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.idem", "account"),
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.idem", "created_at"),
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

// Test_CM_AccCMPolicyAttachment_OutOfBandDeletion verifies that Read() calls RemoveResource
// on 404 and plans recreation after the attachment is deleted out-of-band.
func Test_CM_AccCMPolicyAttachment_OutOfBandDeletion(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-test-attach-pol-oob-%d", time.Now().Unix())
	var attachmentID string

	policyConfig := fmt.Sprintf(`
resource "ciphertrust_policies" "oob_pol" {
  name    = %q
  actions = ["CreateKey"]
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "oob" {
  policy = ciphertrust_policies.oob_pol.id
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.oob_pol]
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + policyConfig,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.oob", "id"),
					func(s *terraform.State) error {
						rs := s.RootModule().Resources["ciphertrust_policy_attachments.oob"]
						if rs == nil {
							return fmt.Errorf("ciphertrust_policy_attachments.oob not found in state")
						}
						attachmentID = rs.Primary.ID
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
					_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), common.URL_CM_POLICY_ATTACHMENTS+"/"+attachmentID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccPolicyAttachment_RequiresReplace verifies that changing any immutable field on
// ciphertrust_policy_attachments cleanly triggers a replacement plan (-/+) instead of failing.
func Test_CM_AccPolicyAttachment_RequiresReplace(t *testing.T) {
	RequireCM(t)
	policyName1 := fmt.Sprintf("tf-replace-policy1-%d", time.Now().Unix())
	policyName2 := fmt.Sprintf("tf-replace-policy2-%d", time.Now().Unix())

	config1 := fmt.Sprintf(`
resource "ciphertrust_policies" "p1" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policies" "p2" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.p1, ciphertrust_policies.p2]
}
`, policyName1, policyName2, policyName1)

	config2 := fmt.Sprintf(`
resource "ciphertrust_policies" "p1" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policies" "p2" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = %q
  principal_selector = {
    acct = "pers-jsmith"
    user = "apitestuser"
  }
  depends_on = [ciphertrust_policies.p1, ciphertrust_policies.p2]
}
`, policyName1, policyName2, policyName2)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + config1,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.attachment", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "policy", policyName1),
				),
			},
			{
				Config: providerConfig + config2,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.attachment", "id"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "policy", policyName2),
				),
			},
		},
	})
}
