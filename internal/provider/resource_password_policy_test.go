package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMPassordPolicy(t *testing.T) {
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

// TestAccCipherTrustPasswordPolicy_drift verifies that Read() surfaces out-of-band
// changes to all nine configured numeric fields and failed_logins_lockout_thresholds.
func TestAccCipherTrustPasswordPolicy_drift(t *testing.T) {
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

// TestAccCipherTrustPasswordPolicy_noDefaultDrift confirms that unconfigured Optional
// Int64 fields do not drift when CM returns server defaults (typically 0 or []).
func TestAccCipherTrustPasswordPolicy_noDefaultDrift(t *testing.T) {
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

// TestAccCipherTrustPasswordPolicy_oobDelete verifies that Read() handles a 404 cleanly
// when a non-global policy has been deleted out-of-band.
func TestAccCipherTrustPasswordPolicy_oobDelete(t *testing.T) {
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
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
