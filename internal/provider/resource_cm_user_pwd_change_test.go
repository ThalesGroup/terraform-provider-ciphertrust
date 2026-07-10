package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Test_CM_CipherTrust_CMUserPasswordChange_OptionalFieldAdded_ForcesReplacement verifies that adding
// an optional field (password_hint) to an existing password-change resource forces a destroy+recreate plan.
// This resource uses CMClientBootstrap and requires bootstrap mode (provider bootstrap = "yes").
// Skipped when TEST_CM_BOOTSTRAP_PASSWORD or TEST_CM_BOOTSTRAP_NEW_PASSWORD are not set.
func Test_CM_CipherTrust_CMUserPasswordChange_OptionalFieldAdded_ForcesReplacement(t *testing.T) {
	RequireCM(t)

	currentPwd := os.Getenv("TEST_CM_BOOTSTRAP_PASSWORD")
	if currentPwd == "" {
		t.Skip("skipping: TEST_CM_BOOTSTRAP_PASSWORD not set")
	}
	newPwd := os.Getenv("TEST_CM_BOOTSTRAP_NEW_PASSWORD")
	if newPwd == "" {
		t.Skip("skipping: TEST_CM_BOOTSTRAP_NEW_PASSWORD not set")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: bootstrapProviderConfig() + `
variable "test_current_password" {
  type      = string
  sensitive = true
}
variable "test_new_password" {
  type      = string
  sensitive = true
}
resource "ciphertrust_cm_user_password_change" "test" {
  username     = "localadmin"
  password     = var.test_current_password
  new_password = var.test_new_password
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_user_password_change.test", "username", "localadmin"),
				),
			},
			{
				// Adding password_hint (null→value) must force a replacement plan.
				Config: bootstrapProviderConfig() + `
variable "test_current_password" {
  type      = string
  sensitive = true
}
variable "test_new_password" {
  type      = string
  sensitive = true
}
resource "ciphertrust_cm_user_password_change" "test" {
  username      = "localadmin"
  password      = var.test_current_password
  new_password  = var.test_new_password
  password_hint = "My hint"
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
