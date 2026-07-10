package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

func Test_CM_AccCMPolicyAttachment_drift(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-acc-attach-drift-pol-%d", time.Now().Unix())

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
  actions    = ["CreateKey"]
  resources  = ["kylo://"]
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.test", "actions.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.test", "resources.#", "1"),
				),
			},
			{
				// ciphertrust_policy_attachments has no PATCH endpoint so OOB updates cannot
				// be applied. Instead, verify that changing 'actions' in Terraform config
				// triggers ImmutableList() at plan time — no API call is made.
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
  actions    = ["CreateKey", "DeleteKey"]
  resources  = ["kylo://"]
  depends_on = [ciphertrust_policies.test]
}
`, policyName, policyName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
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
				Config:      updatedConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
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
				Config:      changedPolicyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
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
				Config:      changedPolicyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
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
				Config:      step2Config,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_PolicyAttachment_ImmutableActions_NullToNonNull verifies that adding actions
// to an attachment where it was null in prior state fires the ImmutableList modifier at plan
// time after the IsNull→IsUnknown fix.
func Test_CM_CipherTrust_PolicyAttachment_ImmutableActions_NullToNonNull(t *testing.T) {
	RequireCM(t)

	policyID := os.Getenv("CM_POLICY_ID")
	principalUser := os.Getenv("CM_PRINCIPAL_USER")
	if policyID == "" || principalUser == "" {
		t.Skip("Skipping: CM_POLICY_ID and CM_PRINCIPAL_USER must be set")
	}

	step1Config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policy_attachments" "test_actions" {
  policy             = %q
  principal_selector = { user = %q }
}
`, policyID, principalUser)

	step2Config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policy_attachments" "test_actions" {
  policy             = %q
  principal_selector = { user = %q }
  actions            = ["CreateKey"]
}
`, policyID, principalUser)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: step1Config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.test_actions", "id"),
				),
			},
			{
				Config:      step2Config,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}
