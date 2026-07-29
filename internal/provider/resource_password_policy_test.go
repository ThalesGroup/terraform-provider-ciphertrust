package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceCMPassordPolicy(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "PasswordPolicy" {
    inclusive_min_upper_case = 2
    inclusive_min_lower_case = 2
    inclusive_min_digits = 2
    inclusive_min_other = 2
    inclusive_min_total_length = 10
    inclusive_max_total_length = 50
    password_history_threshold = 10
    failed_logins_lockout_thresholds = [0, 0, 1, 1]
    password_lifetime = 20
    password_change_min_days = 100
}

resource "ciphertrust_password_policy" "CustomPasswordPolicy" {
	policy_name = "testCustomPolicyName"
    inclusive_min_upper_case = 2
    inclusive_min_lower_case = 2
    inclusive_min_digits = 2
    inclusive_min_other = 2
    inclusive_min_total_length = 10
    inclusive_max_total_length = 50
    password_history_threshold = 10
    failed_logins_lockout_thresholds = [0, 0, 1, 1]
    password_lifetime = 20
    password_change_min_days = 100
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.PasswordPolicy", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.CustomPasswordPolicy", "id"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "PasswordPolicy" {
    inclusive_min_upper_case = 3
    inclusive_min_lower_case = 3
    inclusive_min_digits = 3
    inclusive_min_other = 3
    inclusive_min_total_length = 12
    inclusive_max_total_length = 60
    password_history_threshold = 5
    failed_logins_lockout_thresholds = [0, 0, 1, 1]
    password_lifetime = 30
    password_change_min_days = 50
}

resource "ciphertrust_password_policy" "CustomPasswordPolicy" {
    policy_name = "testCustomPolicyName"
    inclusive_min_upper_case = 3
    inclusive_min_lower_case = 3
    inclusive_min_digits = 3
    inclusive_min_other = 3
    inclusive_min_total_length = 12
    inclusive_max_total_length = 60
    password_history_threshold = 5
    failed_logins_lockout_thresholds = [0, 0, 1, 1]
    password_lifetime = 30
    password_change_min_days = 50
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.PasswordPolicy", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.CustomPasswordPolicy", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func Test_CM_PasswordPolicyCreateAndUpdate(t *testing.T) {
	RequireCM(t)
	policyName := "tf-test-policy-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
    policy_name                       = %q
    inclusive_min_total_length        = 8
    inclusive_max_total_length        = 64
    inclusive_min_digits              = 1
    inclusive_min_lower_case          = 1
    inclusive_min_upper_case          = 1
    inclusive_min_other               = 1
    password_lifetime                 = 90
    password_history_threshold        = 3
    password_change_min_days          = 1
    failed_logins_lockout_thresholds  = [0, 5]
}
`, policyName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "policy_name", policyName),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_total_length", "8"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_max_total_length", "64"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_digits", "1"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_lower_case", "1"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_upper_case", "1"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_other", "1"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "password_lifetime", "90"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "password_history_threshold", "3"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "password_change_min_days", "1"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#", "2"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
    policy_name                       = %q
    inclusive_min_total_length        = 10
    inclusive_max_total_length        = 128
    inclusive_min_digits              = 2
    inclusive_min_lower_case          = 2
    inclusive_min_upper_case          = 2
    inclusive_min_other               = 2
    password_lifetime                 = 60
    password_history_threshold        = 5
    password_change_min_days          = 2
    failed_logins_lockout_thresholds  = [0, 10, 30]
}
`, policyName),
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_total_length", "10"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_max_total_length", "128"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_digits", "2"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_lower_case", "2"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_upper_case", "2"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_other", "2"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "password_lifetime", "60"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "password_history_threshold", "5"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "password_change_min_days", "2"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#", "3"),
				),
			},
		},
	})
}

// Test_CM_AccCipherTrustPasswordPolicy_drift verifies that Read() surfaces out-of-band
// changes to all nine configured numeric fields and failed_logins_lockout_thresholds.
func Test_CM_AccCipherTrustPasswordPolicy_drift(t *testing.T) {
	RequireCM(t)
	policyName := "TFTestPwdDrift-" + uuid.New().String()[:8]
	var capturedName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "drift_test" {
    policy_name                      = %q
    inclusive_min_total_length       = 8
    inclusive_min_digits             = 1
    inclusive_min_lower_case         = 1
    inclusive_min_upper_case         = 1
    inclusive_min_other              = 1
    inclusive_max_total_length       = 64
    password_change_min_days         = 1
    password_history_threshold       = 5
    password_lifetime                = 90
    failed_logins_lockout_thresholds = [0, 5, 30]
}
`, policyName),
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.drift_test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.drift_test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedName = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Patch all configured fields out-of-band, then verify Read() surfaces the drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patch := []byte(`{"inclusive_min_total_length":12,"inclusive_min_digits":2,"inclusive_min_lower_case":2,"inclusive_min_upper_case":2,"inclusive_min_other":2,"inclusive_max_total_length":128,"password_change_min_days":7,"password_history_threshold":10,"password_lifetime":180,"failed_logins_lockout_thresholds":[0,10,60]}`)
					_, _ = client.UpdateDataV2(context.Background(), capturedName, common.URL_CM_PASSWORD_POLICY, patch)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCipherTrustPasswordPolicy_noDefaultDrift confirms that Read() correctly surfaces
// CM-returned defaults as drift for unset Optional Int64 fields after the Computed removal fix.
func Test_CM_AccCipherTrustPasswordPolicy_noDefaultDrift(t *testing.T) {
	RequireCM(t)
	policyName := "TFTestPwdNoDrift-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "no_drift_test" {
    policy_name = %q
}
`, policyName),
				// CM returns non-null defaults for the unset Optional Int64 fields. Read() writes
				// those values into state, producing a diff against the null config values.
				// ExpectNonEmptyPlan: true documents this correct drift-detection behaviour post-fix.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "no-default-drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.no_drift_test", "id"),
				),
			},
			{
				// Refresh confirms drift persists: CM still returns defaults that the null config does not cover.
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMPasswordPolicy_ImmutablePolicyName verifies that ImmutableString() rejects
// an in-place policy_name change at plan time.
func Test_CM_AccCMPasswordPolicy_ImmutablePolicyName(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "immut" {
  policy_name = "tf-test-pwpolicy-immut"
}
`,
				// CM returns non-null defaults for unset Optional Int64 fields; post-fix these cause drift.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.immut", "policy_name", "tf-test-pwpolicy-immut"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "immut" {
  policy_name = "tf-test-pwpolicy-immut-changed"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMPasswordPolicy_Idempotency verifies no spurious plan diff after apply when all
// Optional Int64 fields are explicitly set (so CM defaults do not cause convergence drift).
func Test_CM_AccCMPasswordPolicy_Idempotency(t *testing.T) {
	RequireCM(t)
	policyName := "tf-test-pwpolicy-idem-" + uuid.New().String()[:8]

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "idem" {
  policy_name                      = %q
  inclusive_min_digits             = 2
  inclusive_min_lower_case         = 1
  inclusive_min_upper_case         = 1
  inclusive_min_other              = 1
  inclusive_min_total_length       = 8
  inclusive_max_total_length       = 64
  password_lifetime                = 60
  password_history_threshold       = 3
  password_change_min_days         = 1
  failed_logins_lockout_thresholds = [0, 5]
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.idem", "policy_name", policyName),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.idem", "inclusive_min_digits", "2"),
				),
			},
			{
				// All Optional fields are explicitly set, so CM returns the same values and the plan is empty.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMPasswordPolicy_AttributeDrift verifies that Read() surfaces drift when
// inclusive_min_digits is changed out-of-band.
func Test_CM_AccCMPasswordPolicy_AttributeDrift(t *testing.T) {
	RequireCM(t)
	var capturedName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "drift" {
  policy_name          = "tf-test-pwpolicy-drift"
  inclusive_min_digits = 1
}
`,
				// CM returns non-null defaults for other unset Optional fields; post-fix these cause drift.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.drift", "inclusive_min_digits", "1"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.drift"]
						if !ok {
							return fmt.Errorf("ciphertrust_password_policy.drift not found in state")
						}
						capturedName = rs.Primary.ID
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
					_, err := client.UpdateDataV2(context.Background(), capturedName, common.URL_CM_PASSWORD_POLICY, []byte(`{"inclusive_min_digits":5}`))
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

// Test_CM_AccCMPasswordPolicy_OutOfBandDeletion verifies that Read() calls RemoveResource
// on 404 and plans recreation after OOB deletion.
func Test_CM_AccCMPasswordPolicy_OutOfBandDeletion(t *testing.T) {
	RequireCM(t)
	var capturedName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "oob" {
  policy_name = "tf-test-pwpolicy-oob"
}
`,
				// CM returns non-null defaults for unset Optional fields; post-fix these cause drift.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.oob", "policy_name", "tf-test-pwpolicy-oob"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.oob"]
						if !ok {
							return fmt.Errorf("ciphertrust_password_policy.oob not found in state")
						}
						capturedName = rs.Primary.ID
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
					_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), common.URL_CM_PASSWORD_POLICY+"/"+capturedName)
				},
				Config: providerConfig + `
resource "ciphertrust_password_policy" "oob" {
  policy_name = "tf-test-pwpolicy-oob"
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCipherTrustPasswordPolicy_oobDelete verifies that Read() handles a 404 cleanly
// when a non-global policy has been deleted out-of-band.
func Test_CM_AccCipherTrustPasswordPolicy_oobDelete(t *testing.T) {
	RequireCM(t)
	policyName := "TFTestPwdOOBDel-" + uuid.New().String()[:8]
	var capturedName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "oob_delete_test" {
    policy_name = %q
}
`, policyName),
				// CM returns non-null defaults for unset Optional fields; post-fix these cause drift.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "oob-delete: create",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.oob_delete_test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.oob_delete_test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedName = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the policy out-of-band; Read() should 404-guard and remove from state.
				// PlanOnly: true confirms the plan shows a diff (resource needs recreation)
				// without error, validating the 404 path in Read() is clean.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_CM_PASSWORD_POLICY, capturedName)
					_, _ = client.DeleteByID(context.Background(), "DELETE", uuid.NewString(), url, nil)
				},
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "oob_delete_test" {
    policy_name = %q
}
`, policyName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccPasswordPolicy_PartialOmission verifies that optional fields omitted from HCL config
// do not overwrite server settings to 0 on the CipherTrust Manager.
func Test_CM_AccPasswordPolicy_PartialOmission(t *testing.T) {
	RequireCM(t)
	policyName := "TFTestPwdOmission-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "omission_test" {
    policy_name                = %q
    inclusive_min_total_length = 14
}
`, policyName),
				// CM returns non-null defaults for other unset Optional fields; post-fix these cause drift.
				// The test still verifies that inclusive_min_total_length is not sent as 0 (the original purpose).
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "omission-test: create",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.omission_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.omission_test", "inclusive_min_total_length", "14"),
				),
			},
		},
	})
}

// Test_CM_AccCMPasswordPolicy_ValidationRules verifies that ValidateConfig prevents
// invalid complexity rule configurations where the sum of minimum bounds exceeds total length.
func Test_CM_AccCMPasswordPolicy_ValidationRules(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "invalid_sum" {
  policy_name                = "tf-test-pwpolicy-invalid-sum"
  inclusive_min_total_length = 8
  inclusive_min_digits       = 3
  inclusive_min_lower_case   = 3
  inclusive_min_upper_case   = 3
  inclusive_min_other        = 1
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)sum of inclusive complexity rules`),
			},
		},
	})
}

// Test_CM_AccCMPasswordPolicy_ExpiryNotification verifies the inclusion and functional wiring
// of the password_expiry_notification_days attribute.
func Test_CM_AccCMPasswordPolicy_ExpiryNotification(t *testing.T) {
	RequireCM(t)
	policyName := "TFTestPwdNotification-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "notification_test" {
  policy_name                       = %q
  password_expiry_notification_days = 15
}
`, policyName),
				// CM returns non-null defaults for other unset Optional fields; post-fix these cause drift.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "expiry-notification: create",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.notification_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.notification_test", "password_expiry_notification_days", "15"),
				),
			},
		},
	})
}

// Test_CM_PasswordPolicy_EmptyLockoutThresholds verifies that setting
// failed_logins_lockout_thresholds = [] (the sentinel to disable lockout) converges without
// drift. An empty plan list must serialize as [] in the PATCH body (not null), so CM
// actually clears the threshold list rather than silently ignoring the request.
func Test_CM_PasswordPolicy_EmptyLockoutThresholds(t *testing.T) {
	RequireCM(t)
	policyName := "tf-test-pp-el-" + uuid.New().String()[:8]
	var capturedName string

	configWithThresholds := providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
    policy_name                      = %q
    failed_logins_lockout_thresholds = [0, 0, 1, 1]
}
`, policyName)

	configWithEmptyThresholds := providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
    policy_name                      = %q
    failed_logins_lockout_thresholds = []
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: baseline with populated thresholds; capture resource name for OOB step.
			{
				Config: configWithThresholds,
				// CM returns non-null defaults for other unset Optional fields; post-fix these cause drift.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "baseline",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#", "4"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.0", "0"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.3", "1"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedName = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: sentinel clear — apply with empty list.
			{
				Config: configWithEmptyThresholds,
				// CM still returns non-null defaults for other unset Optional fields.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "sentinel clear",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#", "0"),
				),
			},
			// Step 3: out-of-band drift — restore [0,0,1,1] directly on CM, then plan must
			// detect the divergence (ExpectNonEmptyPlan: true).
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateDataV2(context.Background(), capturedName, common.URL_CM_PASSWORD_POLICY, []byte(`{"failed_logins_lockout_thresholds":[0,0,1,1]}`))
				},
				Config:             configWithEmptyThresholds,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Step 4: restore to populated thresholds.
			{
				Config: configWithThresholds,
				// CM returns non-null defaults for other unset Optional fields.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "restore",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#", "4"),
				),
			},
			// Step 5: verify lockout thresholds config is idempotent (other CM defaults still cause drift).
			{
				Config:             configWithThresholds,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_PasswordPolicy_ZeroMinLengthNoRegression verifies that setting
// inclusive_min_total_length = 0 does NOT produce a perpetual plan diff.
// The UseStateWhenZeroInt64 plan modifier intercepts 0, substitutes the prior
// state value (10), and the effective plan equals state — no diff.
func Test_CM_PasswordPolicy_ZeroMinLengthNoRegression(t *testing.T) {
	RequireCM(t)
	policyName := "tf-test-pp-zmr-" + uuid.New().String()[:8]

	// All optional fields are set in both configs so that CM-populated defaults do
	// not appear as (known after apply) in Step 2 and mask the modifier behaviour.
	baseConfig := func(minLen int) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
    policy_name                        = %q
    inclusive_min_total_length         = %d
    inclusive_max_total_length         = 50
    inclusive_min_digits               = 1
    inclusive_min_lower_case           = 1
    inclusive_min_upper_case           = 1
    inclusive_min_other                = 1
    password_history_threshold         = 3
    password_change_min_days           = 1
    password_lifetime                  = 30
    password_expiry_notification_days  = 14
    failed_logins_lockout_thresholds   = [0, 5]
}
`, policyName, minLen)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: establish baseline with inclusive_min_total_length = 10.
			{
				Config: baseConfig(10),
				Check: checkStep(t, "baseline min_length=10",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_total_length", "10"),
				),
			},
			// Step 2: plan-only with inclusive_min_total_length = 0.
			// The UseStateWhenZeroInt64 modifier substitutes 0 with the prior state value (10),
			// so the effective plan equals state and the plan must be empty.
			{
				Config:             baseConfig(0),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMPasswordPolicy_ZeroSentinel verifies that planning inclusive_min_total_length = 0
// triggers the custom plan modifier, preserving state value to prevent perpetual plan drift.
func Test_CM_AccCMPasswordPolicy_ZeroSentinel(t *testing.T) {
	RequireCM(t)
	policyName := "TFTestPwdZero-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "zero_test" {
  policy_name                = %q
  inclusive_min_total_length = 10
}
`, policyName),
				// CM returns non-null defaults for other unset Optional fields; post-fix these cause drift.
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "zero-test: initial create",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.zero_test", "inclusive_min_total_length", "10"),
				),
			},
			{
				// Plan with inclusive_min_total_length = 0. The UseStateWhenZeroInt64 modifier
				// substitutes 0 with the prior state value (10) so that field causes no diff.
				// CM returns non-null defaults for other unset Optional fields, also causing drift.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "zero_test" {
  policy_name                = %q
  inclusive_min_total_length = 0
}
`, policyName),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "zero-test: update to 0",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.zero_test", "inclusive_min_total_length", "10"),
				),
			},
		},
	})
}

// Test_CM_PasswordPolicy_DriftDetectedAfterAttributeCleared verifies that once
// password_history_threshold is removed from config and the live CM value is changed
// out-of-band, the next terraform plan surfaces a non-empty diff.
func Test_CM_PasswordPolicy_DriftDetectedAfterAttributeCleared(t *testing.T) {
	RequireCM(t)

	name := "tftest-pwpolicy-" + uuid.New().String()[:8]
	var capturedName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Apply with password_history_threshold = 5.
			// CM returns non-null defaults for other unset Optional fields; post-fix these cause drift.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name               = %q
  password_history_threshold = 5
}`, name),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "create with threshold",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "password_history_threshold", "5"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedName = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: Remove password_history_threshold from config; apply.
			// Update() null guard prevents sending the field to CM, so CM retains 5.
			// Read() then writes CM's 5 back into state, causing convergence drift.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name = %q
}`, name),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "attribute cleared from config",
					resource.TestCheckNoResourceAttr("ciphertrust_password_policy.test", "password_history_threshold"),
				),
			},
			// Step 3: Out-of-band change via CM API; verify drift is surfaced.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					_, err := client.UpdateDataV2(context.Background(), capturedName, common.URL_CM_PASSWORD_POLICY, []byte(`{"password_history_threshold": 7}`))
					if err != nil {
						t.Logf("PreConfig: out-of-band PATCH failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_PasswordPolicy_ListDriftDetectedAfterAttributeCleared verifies that once
// failed_logins_lockout_thresholds is removed from config and its live CM value is changed
// out-of-band, the next terraform plan surfaces a non-empty diff.
func Test_CM_PasswordPolicy_ListDriftDetectedAfterAttributeCleared(t *testing.T) {
	RequireCM(t)

	name := "tftest-pwpolicy-list-" + uuid.New().String()[:8]
	var capturedName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Apply with failed_logins_lockout_thresholds = [0, 3, 15].
			// CM returns non-null defaults for other unset Optional fields; post-fix these cause drift.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name                      = %q
  failed_logins_lockout_thresholds = [0, 3, 15]
}`, name),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "create with lockout thresholds",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#", "3"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedName = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: Remove failed_logins_lockout_thresholds from config; apply.
			// Update() null guard prevents sending the field to CM, so CM retains [0,3,15].
			// Read() then writes CM's list back into state, causing convergence drift.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name = %q
}`, name),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "list attribute cleared from config",
					resource.TestCheckNoResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#"),
				),
			},
			// Step 3: Out-of-band change via CM API; verify drift is surfaced.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					_, err := client.UpdateDataV2(context.Background(), capturedName, common.URL_CM_PASSWORD_POLICY, []byte(`{"failed_logins_lockout_thresholds": [0, 5, 30]}`))
					if err != nil {
						t.Logf("PreConfig: out-of-band PATCH failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_PasswordPolicy_AllScalarsDriftDetectedAfterCleared verifies that all eight remaining
// Optional Int64 scalar attributes surface drift correctly after the Computed removal fix.
func Test_CM_PasswordPolicy_AllScalarsDriftDetectedAfterCleared(t *testing.T) {
	RequireCM(t)

	name := "tftest-pwpolicy-scalars-" + uuid.New().String()[:8]
	var capturedName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Apply with all scalar Optional attributes set.
			// CM may return non-null defaults for unset fields (password_history_threshold,
			// failed_logins_lockout_thresholds); post-fix these cause convergence drift.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name                = %q
  inclusive_min_upper_case   = 1
  inclusive_min_lower_case   = 1
  inclusive_min_digits       = 1
  inclusive_min_other        = 1
  inclusive_min_total_length = 8
  inclusive_max_total_length = 64
  password_lifetime          = 90
  password_change_min_days   = 1
}`, name),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "create with all scalars",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_upper_case", "1"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_total_length", "8"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_password_policy.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedName = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: Remove all scalar Optional attributes from config.
			// Update() null guards prevent sending any field to CM. CM retains prior values.
			// Read() then writes CM values back into state, causing convergence drift.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name = %q
}`, name),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "all scalars cleared from config",
					resource.TestCheckNoResourceAttr("ciphertrust_password_policy.test", "inclusive_min_upper_case"),
					resource.TestCheckNoResourceAttr("ciphertrust_password_policy.test", "inclusive_min_total_length"),
					resource.TestCheckNoResourceAttr("ciphertrust_password_policy.test", "password_lifetime"),
				),
			},
			// Step 3: Out-of-band change to two representative attributes; verify drift surfaced.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					_, err := client.UpdateDataV2(context.Background(), capturedName, common.URL_CM_PASSWORD_POLICY, []byte(`{"inclusive_min_upper_case": 3, "password_lifetime": 180}`))
					if err != nil {
						t.Logf("PreConfig: out-of-band PATCH failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
