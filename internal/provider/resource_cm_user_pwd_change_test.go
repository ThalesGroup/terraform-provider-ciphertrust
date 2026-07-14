package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// generateComplexPassword returns a random password that satisfies typical CM
// password policy: min 12 chars, at least one uppercase, lowercase, digit, and
// special character.  Uses acctest.RandStringFromCharSet for the random portion
// so no two test runs share the same alternate credential.
func generateComplexPassword() string {
	// Fixed prefix guarantees all required character classes.
	// Random alphanumeric suffix ensures uniqueness across test runs.
	return "Tf@1" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
}

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
				// Adding password_hint (null→value) on an existing resource must produce an
				// immutable plan-time error now that password_hint uses modifiers.ImmutableString().
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
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
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

// tfaccPwdChangeVarDecls is the variable block shared across all TestAcc_CMUserPasswordChange_* configs.
const tfaccPwdChangeVarDecls = `
variable "tfacc_pwdchg_password" {
  type      = string
  sensitive = true
}
variable "tfacc_pwdchg_new_password" {
  type      = string
  sensitive = true
}
`

// tfaccPwdChangeAltVarDecls adds the alternate-value variables used in PlanOnly/ExpectError steps.
const tfaccPwdChangeAltVarDecls = `
variable "tfacc_pwdchg_alt_password" {
  type      = string
  sensitive = true
}
variable "tfacc_pwdchg_alt_new_password" {
  type      = string
  sensitive = true
}
`

// TestAcc_CMUserPasswordChange_immutable verifies that changing any immutable field on a
// ciphertrust_cm_user_password_change resource produces a plan-time error.
// Required env vars: TF_ACC_CM_TEST_USERNAME, TF_ACC_CM_TEST_PASSWORD, TF_ACC_CM_TEST_NEW_PASSWORD.
func TestAcc_CMUserPasswordChange_immutable(t *testing.T) {
	RequireCM(t)

	username := os.Getenv("TF_ACC_CM_TEST_USERNAME")
	password := os.Getenv("TF_ACC_CM_TEST_PASSWORD")
	newPassword := os.Getenv("TF_ACC_CM_TEST_NEW_PASSWORD")
	if username == "" || password == "" || newPassword == "" {
		t.Skip("TF_ACC_CM_TEST_USERNAME, TF_ACC_CM_TEST_PASSWORD, or TF_ACC_CM_TEST_NEW_PASSWORD not set — skipping TestAcc_CMUserPasswordChange_immutable")
	}

	altPassword := os.Getenv("TF_ACC_CM_TEST_ALT_PASSWORD")
	if altPassword == "" {
		altPassword = generateComplexPassword()
	}
	altNewPassword := os.Getenv("TF_ACC_CM_TEST_ALT_NEW_PASSWORD")
	if altNewPassword == "" {
		altNewPassword = generateComplexPassword()
	}

	t.Setenv("TF_VAR_tfacc_pwdchg_password", password)
	t.Setenv("TF_VAR_tfacc_pwdchg_new_password", newPassword)
	t.Setenv("TF_VAR_tfacc_pwdchg_alt_password", altPassword)
	t.Setenv("TF_VAR_tfacc_pwdchg_alt_new_password", altNewPassword)

	baseConfig := bootstrapProviderConfig() + tfaccPwdChangeVarDecls + `
resource "ciphertrust_cm_user_password_change" "test" {
  username      = "` + username + `"
  password      = var.tfacc_pwdchg_password
  new_password  = var.tfacc_pwdchg_new_password
  auth_domain   = "root"
  password_hint = "hint1"
}
`

	expectImmutable := regexp.MustCompile(`(?i)cannot be changed after creation`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Apply base config.
			{
				Config: baseConfig,
			},
			// Step 2: Change username → immutable.
			{
				Config: bootstrapProviderConfig() + tfaccPwdChangeVarDecls + `
resource "ciphertrust_cm_user_password_change" "test" {
  username      = "changed_user"
  password      = var.tfacc_pwdchg_password
  new_password  = var.tfacc_pwdchg_new_password
  auth_domain   = "root"
  password_hint = "hint1"
}
`,
				PlanOnly:    true,
				ExpectError: expectImmutable,
			},
			// Step 3: Change password → immutable.
			{
				Config: bootstrapProviderConfig() + tfaccPwdChangeVarDecls + tfaccPwdChangeAltVarDecls + `
resource "ciphertrust_cm_user_password_change" "test" {
  username      = "` + username + `"
  password      = var.tfacc_pwdchg_alt_password
  new_password  = var.tfacc_pwdchg_new_password
  auth_domain   = "root"
  password_hint = "hint1"
}
`,
				PlanOnly:    true,
				ExpectError: expectImmutable,
			},
			// Step 4: Change new_password → immutable.
			{
				Config: bootstrapProviderConfig() + tfaccPwdChangeVarDecls + tfaccPwdChangeAltVarDecls + `
resource "ciphertrust_cm_user_password_change" "test" {
  username      = "` + username + `"
  password      = var.tfacc_pwdchg_password
  new_password  = var.tfacc_pwdchg_alt_new_password
  auth_domain   = "root"
  password_hint = "hint1"
}
`,
				PlanOnly:    true,
				ExpectError: expectImmutable,
			},
			// Step 5: Change auth_domain → immutable.
			{
				Config: bootstrapProviderConfig() + tfaccPwdChangeVarDecls + `
resource "ciphertrust_cm_user_password_change" "test" {
  username      = "` + username + `"
  password      = var.tfacc_pwdchg_password
  new_password  = var.tfacc_pwdchg_new_password
  auth_domain   = "local"
  password_hint = "hint1"
}
`,
				PlanOnly:    true,
				ExpectError: expectImmutable,
			},
			// Step 6: Change password_hint → immutable.
			{
				Config: bootstrapProviderConfig() + tfaccPwdChangeVarDecls + `
resource "ciphertrust_cm_user_password_change" "test" {
  username      = "` + username + `"
  password      = var.tfacc_pwdchg_password
  new_password  = var.tfacc_pwdchg_new_password
  auth_domain   = "root"
  password_hint = "hint2"
}
`,
				PlanOnly:    true,
				ExpectError: expectImmutable,
			},
		},
	})
}

// TestAcc_CMUserPasswordChange_idempotency verifies that a second plan with no config changes
// shows no diff after apply, confirming id is correctly hydrated and Read() is stable.
// Required env vars: TF_ACC_CM_TEST_USERNAME, TF_ACC_CM_TEST_PASSWORD, TF_ACC_CM_TEST_NEW_PASSWORD.
func TestAcc_CMUserPasswordChange_idempotency(t *testing.T) {
	RequireCM(t)

	username := os.Getenv("TF_ACC_CM_TEST_USERNAME")
	password := os.Getenv("TF_ACC_CM_TEST_PASSWORD")
	newPassword := os.Getenv("TF_ACC_CM_TEST_NEW_PASSWORD")
	if username == "" || password == "" || newPassword == "" {
		t.Skip("TF_ACC_CM_TEST_USERNAME, TF_ACC_CM_TEST_PASSWORD, or TF_ACC_CM_TEST_NEW_PASSWORD not set — skipping TestAcc_CMUserPasswordChange_idempotency")
	}

	t.Setenv("TF_VAR_tfacc_pwdchg_password", password)
	t.Setenv("TF_VAR_tfacc_pwdchg_new_password", newPassword)

	cfg := bootstrapProviderConfig() + tfaccPwdChangeVarDecls + `
resource "ciphertrust_cm_user_password_change" "test" {
  username     = "` + username + `"
  password     = var.tfacc_pwdchg_password
  new_password = var.tfacc_pwdchg_new_password
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             cfg,
				ExpectNonEmptyPlan: false,
				Check: checkStep(t, "after-create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_user_password_change.test", "id"),
				),
			},
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
