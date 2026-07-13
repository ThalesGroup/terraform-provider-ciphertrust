package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCipherTrust_CMUserPwdChange_ReadStability verifies that a terraform plan
// immediately after apply shows no changes — confirming Read() does not produce
// "Provider produced inconsistent result after apply." This resource is a one-shot
// action with no retrievable server state; Read() preserves state unchanged.
// Skipped unless CM_TEST_PASSWORD_CHANGE=true, TEST_CM_BOOTSTRAP_PASSWORD, and
// TEST_CM_BOOTSTRAP_NEW_PASSWORD are all set.
func TestCipherTrust_CMUserPwdChange_ReadStability(t *testing.T) {
	RequireCM(t)

	if os.Getenv("CM_TEST_PASSWORD_CHANGE") != "true" {
		t.Skip("skipping TestCipherTrust_CMUserPwdChange_ReadStability: CM_TEST_PASSWORD_CHANGE not set to true")
	}
	if os.Getenv("TEST_CM_BOOTSTRAP_PASSWORD") == "" {
		t.Skip("skipping TestCipherTrust_CMUserPwdChange_ReadStability: TEST_CM_BOOTSTRAP_PASSWORD not set")
	}
	if os.Getenv("TEST_CM_BOOTSTRAP_NEW_PASSWORD") == "" {
		t.Skip("skipping TestCipherTrust_CMUserPwdChange_ReadStability: TEST_CM_BOOTSTRAP_NEW_PASSWORD not set")
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
			// Verify that an immediate plan after apply shows no changes.
			// Confirms Read() does not produce a provider inconsistency.
			{
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCipherTrust_CMUserPasswordChange_OptionalFieldAdded_ForcesReplacement verifies that adding
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

// Test_CM_UserPasswordChange_Create verifies that a ciphertrust_cm_user_password_change
// resource can be applied (changing the specified user's password) and that the id field
// is populated in state. This resource is a one-shot action; destroy is a no-op.
// Required env vars: CM_TEST_USERNAME, CM_TEST_OLD_PASSWORD, CM_TEST_NEW_PASSWORD.
func Test_CM_UserPasswordChange_Create(t *testing.T) {
	RequireCM(t)

	username := os.Getenv("CM_TEST_USERNAME")
	if username == "" {
		t.Skip("CM_TEST_USERNAME not set — skipping user-password-change acceptance test")
	}
	if os.Getenv("CM_TEST_OLD_PASSWORD") == "" {
		t.Skip("CM_TEST_OLD_PASSWORD not set — skipping user-password-change acceptance test")
	}
	if os.Getenv("CM_TEST_NEW_PASSWORD") == "" {
		t.Skip("CM_TEST_NEW_PASSWORD not set — skipping user-password-change acceptance test")
	}

	t.Setenv("TF_VAR_cm_pwd_change_username", username)
	t.Setenv("TF_VAR_cm_pwd_change_old_password", os.Getenv("CM_TEST_OLD_PASSWORD"))
	t.Setenv("TF_VAR_cm_pwd_change_new_password", os.Getenv("CM_TEST_NEW_PASSWORD"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserPasswordChangeConfig(),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_user_password_change.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_user_password_change.test", "username", username),
				),
			},
		},
	})
}

func testAccUserPasswordChangeConfig() string {
	return bootstrapProviderConfig() + `
variable "cm_pwd_change_username" {
  type = string
}
variable "cm_pwd_change_old_password" {
  type      = string
  sensitive = true
}
variable "cm_pwd_change_new_password" {
  type      = string
  sensitive = true
}

resource "ciphertrust_cm_user_password_change" "test" {
  username     = var.cm_pwd_change_username
  password     = var.cm_pwd_change_old_password
  new_password = var.cm_pwd_change_new_password
}
`
}
