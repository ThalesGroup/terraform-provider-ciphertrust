package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCMPasswordPolicy_DriftDetection(t *testing.T) {
	RequireCM(t)
	const policyName = "testAccDriftDetectionPolicy"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "test" {
    policy_name        = "` + policyName + `"
    inclusive_min_digits = 1
}
`,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_digits", "1"),
					resource.TestCheckResourceAttrPair("ciphertrust_password_policy.test", "id", "ciphertrust_password_policy.test", "policy_name"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_password_policy" "test" {
    policy_name        = "` + policyName + `"
    inclusive_min_digits = 2
}
`,
				Check: checkStep(t, "step2",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_digits", "2"),
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.test", "id"),
				),
			},
		},
	})
}

func TestAccCMPasswordPolicy_NoPerpetualDiff(t *testing.T) {
	RequireCM(t)
	const policyName = "testAccNoPerpDiffPolicy"
	config := providerConfig + `
resource "ciphertrust_password_policy" "test" {
    policy_name        = "` + policyName + `"
    inclusive_min_digits = 3
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "step1",
					resource.TestCheckResourceAttr("ciphertrust_password_policy.test", "inclusive_min_digits", "3"),
					resource.TestCheckResourceAttrSet("ciphertrust_password_policy.test", "id"),
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
