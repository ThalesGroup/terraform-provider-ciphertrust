package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMPolicyAttachment(t *testing.T) {
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

func TestAccCMPolicyAttachment_DriftRead(t *testing.T) {
	policyName := "tf-test-attach-drift-" + uuid.New().String()[:8]
	policyAddr := "ciphertrust_policies.drift_attach_policy"
	attachAddr := "ciphertrust_policy_attachments.drift_attachment"

	attachConfig := func() string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "drift_attach_policy" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "drift_attachment" {
  policy     = %q
  principal_selector = {
    acct = "pers-testuser"
    user = "apitestuser"
  }
  actions   = ["ReadKey"]
  resources = ["kylo:*:vault:keys:*"]
  depends_on = [ciphertrust_policies.drift_attach_policy]
}
`, policyName, policyName)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: attachConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(policyAddr, "id"),
					resource.TestCheckResourceAttrSet(attachAddr, "id"),
					resource.TestCheckResourceAttr(attachAddr, "policy", policyName),
					resource.TestCheckResourceAttr(attachAddr, "actions.#", "1"),
					resource.TestCheckResourceAttr(attachAddr, "actions.0", "ReadKey"),
					resource.TestCheckResourceAttr(attachAddr, "resources.#", "1"),
					resource.TestCheckResourceAttr(attachAddr, "resources.0", "kylo:*:vault:keys:*"),
					resource.TestCheckResourceAttr(attachAddr, "principal_selector.acct", "pers-testuser"),
					testAccListResourceAttributes(attachAddr),
				),
			},
			{
				// No false drift on subsequent plan — Read() must round-trip all attributes cleanly.
				Config:             attachConfig(),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMPolicyAttachment_Update(t *testing.T) {
	policyName := "tf-test-attach-upd-" + uuid.New().String()[:8]
	attachAddr := "ciphertrust_policy_attachments.update_attachment"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "upd_policy" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "update_attachment" {
  policy     = %q
  principal_selector = {
    user = "apitestuser"
  }
  actions   = ["ReadKey"]
  resources = ["kylo:*:vault:keys:*"]
  depends_on = [ciphertrust_policies.upd_policy]
}
`, policyName, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(attachAddr, "id"),
					resource.TestCheckResourceAttr(attachAddr, "actions.0", "ReadKey"),
					resource.TestCheckResourceAttr(attachAddr, "actions.#", "1"),
					resource.TestCheckResourceAttr(attachAddr, "resources.0", "kylo:*:vault:keys:*"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "upd_policy" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "update_attachment" {
  policy     = %q
  principal_selector = {
    user = "apitestuser"
  }
  actions   = ["ReadKey", "CreateKey"]
  resources = ["kylo:*:vault:keys:*", "kylo:*:vault:secrets:*"]
  depends_on = [ciphertrust_policies.upd_policy]
}
`, policyName, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(attachAddr, "actions.#", "2"),
					resource.TestCheckResourceAttr(attachAddr, "actions.0", "ReadKey"),
					resource.TestCheckResourceAttr(attachAddr, "actions.1", "CreateKey"),
					resource.TestCheckResourceAttr(attachAddr, "resources.#", "2"),
				),
			},
			{
				// Verify no drift after the update.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "upd_policy" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}

resource "ciphertrust_policy_attachments" "update_attachment" {
  policy     = %q
  principal_selector = {
    user = "apitestuser"
  }
  actions   = ["ReadKey", "CreateKey"]
  resources = ["kylo:*:vault:keys:*", "kylo:*:vault:secrets:*"]
  depends_on = [ciphertrust_policies.upd_policy]
}
`, policyName, policyName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
