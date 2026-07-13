package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_ResourceTrialLicense(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_trial_license" "trial_license" {
  }
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.trial_license", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestCMTrialLicenseCreateAndDestroy(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_trial_license" "test" {
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_trial_license.test", "status", "activated"),
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.test", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.test", "description"),
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.test", "activated_at"),
				),
			},
		},
	})
}

// Test_CM_AccCipherTrust_TrialLicense_StableComputedFields verifies that name and description
// do not show as (known after apply) on subsequent plans after the first apply.
func Test_CM_AccCipherTrust_TrialLicense_StableComputedFields(t *testing.T) {
	RequireCM(t)

	cfg := providerConfig + `
resource "ciphertrust_trial_license" "test" {
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_trial_license.test", "status", "activated"),
				),
			},
			// No out-of-band change; name and description must remain stable (no diff).
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.test", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.test", "description"),
				),
			},
		},
	})
}
