package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cmLicenseConfig builds an HCL config for ciphertrust_license.
// The license value is read from the TF_VAR_cm_license_code variable (never interpolated directly).
// bindType is included in the config when non-empty.
func cmLicenseConfig(bindType string) string {
	base := providerConfig + `
variable "cm_license_code" {
  type = string
}

resource "ciphertrust_license" "test" {
  license = var.cm_license_code
`
	if bindType != "" {
		base += `  bind_type = "` + bindType + `"
`
	}
	base += `}
`
	return base
}

// Test_CM_License_WriteOnlyLicenseProducesNoDiff verifies that license is write-only:
// Terraform Core excludes a write-only attribute's own value from diff computation, so
// changing `license` alone (with everything else unchanged) produces an empty plan rather
// than an error or an update. license has no companion `*_version` field and Update()
// unconditionally rejects all changes — the only supported way to change the license is to
// destroy and recreate the resource (e.g. `terraform apply -replace`).
func Test_CM_License_WriteOnlyLicenseProducesNoDiff(t *testing.T) {
	RequireCM(t)

	licenseCode := os.Getenv("TF_ACC_LICENSE_CODE")
	if licenseCode == "" {
		t.Skip("TF_ACC_LICENSE_CODE not set — skipping license write-only acceptance test")
	}
	t.Setenv("TF_VAR_cm_license_code", licenseCode)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmLicenseConfig("instance"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
					resource.TestCheckNoResourceAttr("ciphertrust_license.test", "license"),
				),
			},
			{
				// Change license value — write-only, so no diff is produced and no error occurs.
				Config: providerConfig + `
variable "cm_license_code" {
  type = string
}

resource "ciphertrust_license" "test" {
  license   = "CHANGED-LICENSE-VALUE"
  bind_type = "instance"
}`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_License_ImmutableBindType verifies that ImmutableString() rejects bind_type changes at plan time.
func Test_CM_License_ImmutableBindType(t *testing.T) {
	RequireCM(t)

	licenseCode := os.Getenv("TF_ACC_LICENSE_CODE")
	if licenseCode == "" {
		t.Skip("TF_ACC_LICENSE_CODE not set — skipping license immutability acceptance test")
	}
	t.Setenv("TF_VAR_cm_license_code", licenseCode)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmLicenseConfig("instance"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
				),
			},
			{
				// Change bind_type — ImmutableString() must reject at plan time.
				Config:      cmLicenseConfig("cluster"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_License_Idempotency verifies that after applying a license, a second plan with no config
// changes produces an empty diff (all Computed fields are stable across refreshes).
func Test_CM_License_Idempotency(t *testing.T) {
	RequireCM(t)

	licenseCode := os.Getenv("TF_ACC_LICENSE_CODE")
	if licenseCode == "" {
		t.Skip("TF_ACC_LICENSE_CODE not set — skipping license idempotency acceptance test")
	}
	t.Setenv("TF_VAR_cm_license_code", licenseCode)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmLicenseConfig("instance"),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "hash"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "type"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "state"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "expiration"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "version"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "license_count"),
				),
			},
			{
				// Identical config — verifies no spurious diff from any Computed attribute.
				Config:             cmLicenseConfig("instance"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
