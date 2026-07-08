package provider

import (
	"context"
	"fmt"
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
// removes it from state gracefully instead of returning a hard error.
func Test_CM_CMPolicyAttachmentOutOfBandDeletion(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-oob-policy-%d", time.Now().Unix())

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

	deleteOutOfBand := func(resourceName string) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			rs, ok := s.RootModule().Resources[resourceName]
			if !ok {
				return fmt.Errorf("resource %s not found in state", resourceName)
			}
			id := rs.Primary.ID
			client, ok := createCMClient()
			if !ok {
				t.Skip("Skipping out-of-band deletion test: CM client could not be created (check CIPHERTRUST_* env vars)")
			}
			endpoint := common.URL_CM_POLICY_ATTACHMENTS + "/" + id
			if _, err := client.DeleteByURL(context.Background(), id, endpoint); err != nil {
				return fmt.Errorf("out-of-band delete failed: %s", err)
			}
			return nil
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the attachment, then delete it from CM directly.
			// With the new 404 behavior: Read() adds a warning but keeps the
			// resource in state (no RemoveResource). No diff is produced.
			{
				Config: providerConfig + policyConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.oob_attachment", "id"),
					deleteOutOfBand("ciphertrust_policy_attachments.oob_attachment"),
				),
				ExpectNonEmptyPlan: false,
			},
			// Step 2: RefreshState — Read() gets 404, adds warning, preserves state.
			// No diff because resource is still in state with same values.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
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
