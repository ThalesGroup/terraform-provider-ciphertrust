package provider

import (
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Test_CM_AccCMLicense_ComputedFields verifies that all stable Computed-only fields are
// populated after create and produce no drift on subsequent refresh.
func Test_CM_AccCMLicense_ComputedFields(t *testing.T) {
	RequireCM(t)

	licenseStr := os.Getenv("CIPHERTRUST_TEST_LICENSE")
	if licenseStr == "" {
		t.Skip("CIPHERTRUST_TEST_LICENSE not set — skipping license acceptance test")
	}

	// Pass the license value via TF_VAR so it is never interpolated directly into the HCL string.
	t.Setenv("TF_VAR_test_license", licenseStr)

	licenseConfig := providerConfig + `
variable "test_license" {
  type = string
}

resource "ciphertrust_license" "test" {
  license = var.test_license
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: licenseConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "hash"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "type"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "state"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "expiration"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "version"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "license_count"),
				),
			},
			{
				// Stable Computed-only fields must produce no drift on subsequent refresh.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCipherTrust_License_ImmutableBindType_NullToNonNull verifies that adding bind_type
// to a license resource where it was null in prior state produces a plan-time immutability
// error from the fixed ImmutableString modifier (IsUnknown guard, not IsNull).
func TestCipherTrust_License_ImmutableBindType_NullToNonNull(t *testing.T) {
	RequireCM(t)

	licenseStr := os.Getenv("CM_LICENSE_STRING")
	if licenseStr == "" {
		t.Skip("CM_LICENSE_STRING not set — skipping license immutability acceptance test")
	}

	t.Setenv("TF_VAR_test_license", licenseStr)

	configNoBindType := providerConfig + `
variable "test_license" {
  type = string
}

resource "ciphertrust_license" "test" {
  license = var.test_license
}
`

	configWithBindType := providerConfig + `
variable "test_license" {
  type = string
}

resource "ciphertrust_license" "test" {
  license   = var.test_license
  bind_type = "instance"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: configNoBindType,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
				),
			},
			{
				Config:      configWithBindType,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// TestCipherTrust_License_ImmutableBindType_InitialCreate verifies that supplying bind_type
// on first create succeeds without immutability error, confirming the IsUnknown() guard
// preserves first-create behavior.
func TestCipherTrust_License_ImmutableBindType_InitialCreate(t *testing.T) {
	RequireCM(t)

	licenseStr := os.Getenv("CM_LICENSE_STRING")
	if licenseStr == "" {
		t.Skip("CM_LICENSE_STRING not set — skipping license immutability acceptance test")
	}

	t.Setenv("TF_VAR_test_license", licenseStr)

	configWithBindType := providerConfig + `
variable "test_license" {
  type = string
}

resource "ciphertrust_license" "test" {
  license   = var.test_license
  bind_type = "instance"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: configWithBindType,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_license.test", "bind_type", "instance"),
				),
			},
		},
	})
}
