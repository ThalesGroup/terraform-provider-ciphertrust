package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMPolicyAttachment(t *testing.T) {
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

// TestCMPolicyAttachmentOutOfBandDeletion verifies that when a policy attachment
// is deleted directly on CipherTrust Manager (out-of-band), the next
// terraform refresh removes it from state gracefully instead of returning a
// hard error.
func TestCMPolicyAttachmentOutOfBandDeletion(t *testing.T) {
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
			// ExpectNonEmptyPlan: true because the OOB delete causes the resource
			// to disappear from state during the post-step refresh check.
			{
				Config: providerConfig + policyConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.oob_attachment", "id"),
					deleteOutOfBand("ciphertrust_policy_attachments.oob_attachment"),
				),
				ExpectNonEmptyPlan: true,
			},
			// Step 2: RefreshState — Read() detects 404, removes from state, no error.
			// ExpectNonEmptyPlan: true because after removal the plan shows +create.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			// Step 3: Plan — attachment gone from state, Terraform proposes +create.
			{
				Config:             providerConfig + policyConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
