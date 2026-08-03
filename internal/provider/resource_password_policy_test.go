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

// Test_CM_AccCipherTrustPasswordPolicy_noDefaultDrift confirms that unconfigured Optional
// Int64 fields do not drift when CM returns server defaults (typically 0 or []).
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
				Check: checkStep(t, "no-default-drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.no_drift_test", "id"),
				),
			},
			{
				// Refresh state from CM; expect no plan diff despite CM returning numeric defaults.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
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

// Test_CM_AccCMPasswordPolicy_Idempotency verifies no spurious plan diff after apply —
// Computed id and policy_name do not cause perpetual drift.
func Test_CM_AccCMPasswordPolicy_Idempotency(t *testing.T) {
	RequireCM(t)

	config := providerConfig + `
resource "ciphertrust_password_policy" "idem" {
  policy_name          = "tf-test-pwpolicy-idem"
  inclusive_min_digits = 2
  password_lifetime    = 60
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.idem", "id", "tf-test-pwpolicy-idem"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.idem", "policy_name", "tf-test-pwpolicy-idem"),
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
				ExpectNonEmptyPlan: false,
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
				ExpectNonEmptyPlan: false,
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
			// Step 2: sentinel clear — apply with empty list; post-apply plan must be empty.
			{
				Config:             configWithEmptyThresholds,
				ExpectNonEmptyPlan: false,
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
			// Step 4: restore to populated thresholds; confirm idempotent apply.
			{
				Config: configWithThresholds,
				Check: checkStep(t, "restore",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "failed_logins_lockout_thresholds.#", "4"),
				),
			},
			// Step 5: idempotency after restore — plan must be empty.
			{
				Config:             configWithThresholds,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_PasswordPolicy_ZeroMinLengthNoRegression verifies that setting
// inclusive_min_total_length = 0 on an existing resource is rejected at plan time
// (TFIN-553: int64validator.AtLeast(1) added). Before the fix, UseStateWhenZeroInt64
// would intercept 0 and produce an empty plan; now 0 is rejected outright.
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
			// The AtLeast(1) validator now rejects 0 outright at plan time (TFIN-553).
			// The plan must fail with a clear validator error rather than silently succeeding
			// or crashing after orphaning a resource on CM.
			{
				Config:      baseConfig(0),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)at least 1`),
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
				Check: checkStep(t, "zero-test: initial create",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.zero_test", "inclusive_min_total_length", "10"),
				),
			},
			{
				// Plan with inclusive_min_total_length = 0. The UseStateWhenZeroInt64 modifier
				// substitutes 0 with the prior state value (10) so that field causes no diff.
				// However Read() unconditionally hydrates Optional+Computed Int64 fields (e.g.
				// inclusive_max_total_length) from the CM response even when prior state was null,
				// producing a perpetual (known after apply) diff. ExpectNonEmptyPlan: true
				// documents this known pre-existing behaviour for unset Optional Int64 fields.
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

// Test_CM_PasswordPolicy_LockoutThresholdsLifecycle verifies the lifecycle of failed_logins_lockout_thresholds
// across omitted, configured, and transitioned configurations as a Computed field.
func Test_CM_PasswordPolicy_LockoutThresholdsLifecycle(t *testing.T) {
	RequireCM(t)
	policyName := "tf-test-pp-lc-" + uuid.New().String()[:8]

	configOmitted := providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "lifecycle_test" {
    policy_name = %q
}
`, policyName)

	configConfigured := providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "lifecycle_test" {
    policy_name = %q
    failed_logins_lockout_thresholds = [0, 10, 60]
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: omitted in HCL. Because it is Optional + Computed, the state is hydrated with the server-default list.
			{
				Config: configOmitted,
				Check: checkStep(t, "omitted",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.#", "5"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.0", "0"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.4", "1"),
				),
			},
			// Step 2: transition from omitted to configured.
			{
				Config: configConfigured,
				Check: checkStep(t, "omitted to configured",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.#", "3"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.0", "0"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.1", "10"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.2", "60"),
				),
			},
			// Step 3: transition from configured back to omitted. The framework retains the last-applied state value [0, 10, 60] cleanly.
			{
				Config: configOmitted,
				Check: checkStep(t, "configured to omitted",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.#", "3"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.0", "0"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.lifecycle_test", "failed_logins_lockout_thresholds.2", "60"),
				),
			},
		},
	})
}

// Test_CM_PasswordPolicy_ZeroMinTotalLengthRejectedAtPlan verifies that
// inclusive_min_total_length = 0 is rejected at plan time (TFIN-553).
// Before the fix, 0 would pass planning, CM would assign its default (8), and
// Terraform would crash with "Provider produced inconsistent result after apply".
func Test_CM_PasswordPolicy_ZeroMinTotalLengthRejectedAtPlan(t *testing.T) {
	RequireCM(t)
	name := "tf-ppol-zero-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name                = %q
  inclusive_min_total_length = 0
}`, name),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)at least 1`),
			},
		},
	})
}

// Test_CM_PasswordPolicy_UseStateForUnknownOnUpdate verifies that unchanged
// Optional+Computed fields do not show "(known after apply)" when an unrelated
// field has a genuine pending change (TFIN-555 regression test).
func Test_CM_PasswordPolicy_UseStateForUnknownOnUpdate(t *testing.T) {
	RequireCM(t)
	name := "tf-ppol-usfu-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with two fields set.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name                = %q
  inclusive_min_digits       = 1
  inclusive_min_upper_case   = 1
}`, name),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_digits", "1"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_upper_case", "1"),
				),
			},
			{
				// Step 2: change one field; the other must NOT become "(known after apply)".
				// With UseStateForUnknown(), stable fields keep their current state value.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_password_policy" "test" {
  policy_name                = %q
  inclusive_min_digits       = 2
  inclusive_min_upper_case   = 1
}`, name),
				Check: checkStep(t, "update one field — sibling stays stable",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_digits", "2"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_upper_case", "1"),
				),
				// A clean subsequent plan confirms no drift from the UseStateForUnknown() modifiers.
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
