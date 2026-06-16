package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccCMPolicyAttachmentCreateWithActions(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachActionsPolicy"
  actions = ["CreateKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachActionsPolicy"
  principal_selector = {
    group = "auditors"
  }
  actions   = ["CreateKey"]
  resources = ["kylo://"]
  depends_on = [ciphertrust_policies.policy]
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "actions.0", "CreateKey"),
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "resources.0", "kylo://"),
				),
			},
			{
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachActionsPolicy"
  actions = ["CreateKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachActionsPolicy"
  principal_selector = {
    group = "auditors"
  }
  actions   = ["CreateKey"]
  resources = ["kylo://"]
  depends_on = [ciphertrust_policies.policy]
}
`,
			},
		},
	})
}

func TestAccCMPolicyAttachmentActionsResourcesDrift(t *testing.T) {
	RequireCM(t)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachDriftPolicy"
  actions = ["CreateKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachDriftPolicy"
  principal_selector = {
    group = "auditors"
  }
  actions   = ["CreateKey"]
  resources = ["kylo://"]
  depends_on = [ciphertrust_policies.policy]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policy_attachments.attachment", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_policy_attachments.attachment"]
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
					// Patch principal_selector OOB — this field IS returned by the GET endpoint
					// so Read() will detect the drift.
					patchPayload := []byte(`{"principalSelector":{"group":"operators"}}`)
					_, _ = client.UpdateDataV2(context.Background(), capturedID, common.URL_CM_POLICY_ATTACHMENTS, patchPayload)
				},
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachDriftPolicy"
  actions = ["CreateKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachDriftPolicy"
  principal_selector = {
    group = "auditors"
  }
  actions   = ["CreateKey"]
  resources = ["kylo://"]
  depends_on = [ciphertrust_policies.policy]
}
`,
			},
		},
	})
}

func TestAccCMPolicyAttachmentActionsUpdate(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachActionsUpdatePolicy"
  actions = ["CreateKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachActionsUpdatePolicy"
  principal_selector = {
    group = "auditors"
  }
  actions = ["CreateKey"]
  depends_on = [ciphertrust_policies.policy]
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "actions.0", "CreateKey"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachActionsUpdatePolicy"
  actions = ["CreateKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachActionsUpdatePolicy"
  principal_selector = {
    group = "auditors"
  }
  actions = ["DeleteKey"]
  depends_on = [ciphertrust_policies.policy]
}
`,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "actions.0", "DeleteKey"),
				),
			},
		},
	})
}

func TestAccCMPolicyAttachmentPrincipalSelectorUpdate(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachSelectorUpdatePolicy"
  actions = ["ReadKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachSelectorUpdatePolicy"
  principal_selector = {
    group = "auditors"
  }
  depends_on = [ciphertrust_policies.policy]
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "principal_selector.group", "auditors"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_policies" "policy" {
  name   = "testAttachSelectorUpdatePolicy"
  actions = ["ReadKey"]
  allow  = true
  effect = "allow"
}

resource "ciphertrust_policy_attachments" "attachment" {
  policy = "testAttachSelectorUpdatePolicy"
  principal_selector = {
    group = "operators"
  }
  depends_on = [ciphertrust_policies.policy]
}
`,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_policy_attachments.attachment", "principal_selector.group", "operators"),
				),
			},
		},
	})
}

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
