package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const trialLicenseResource = "ciphertrust_trial_license.test"

func trialLicenseConfig() string {
	return providerConfig + `
resource "ciphertrust_trial_license" "test" {}
`
}

// TestAccCMTrialLicense_BasicNoDrift verifies that a trial license resource can be
// created and that a subsequent plan shows no drift (Read() correctly round-trips state).
func TestAccCMTrialLicense_BasicNoDrift(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Activate the trial license; verify computed attributes are populated.
			{
				Config: trialLicenseConfig(),
				Check: checkStep(t, "activate trial license",
					resource.TestCheckResourceAttrSet(trialLicenseResource, "id"),
					resource.TestCheckResourceAttrSet(trialLicenseResource, "name"),
					resource.TestCheckResourceAttrSet(trialLicenseResource, "status"),
				),
			},
			// Step 2: No-drift check — same config, plan must be empty.
			{
				Config:             trialLicenseConfig(),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
