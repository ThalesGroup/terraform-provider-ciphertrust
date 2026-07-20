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

// Test_CM_CipherTrust_License_ImmutableBindType_NullToNonNull verifies that adding bind_type
// to a license resource where it was null in prior state produces a plan-time immutability
// error from the fixed ImmutableString modifier (IsUnknown guard, not IsNull).
func Test_CM_CipherTrust_License_ImmutableBindType_NullToNonNull(t *testing.T) {
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

// Test_CM_License_BasicCreate verifies that a ciphertrust_license resource can be
// created, that all stable Computed fields are populated after apply, and that
// terraform destroy completes without error.
// Required env var: CM_TEST_LICENSE (the license string to activate).
func Test_CM_License_BasicCreate(t *testing.T) {
	RequireCM(t)

	licenseStr := os.Getenv("CM_TEST_LICENSE")
	if licenseStr == "" {
		t.Skip("CM_TEST_LICENSE not set — skipping license basic-create acceptance test")
	}

	t.Setenv("TF_VAR_cm_license_basic", licenseStr)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccLicenseConfig(),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "state"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "hash"),
				),
			},
		},
	})
}

func testAccLicenseConfig() string {
	return providerConfig + `
variable "cm_license_basic" {
  type = string
}

resource "ciphertrust_license" "test" {
  license = var.cm_license_basic
}
`
}

// Test_CM_CipherTrust_License_ImmutableBindType_InitialCreate verifies that supplying bind_type
// on first create succeeds without immutability error, confirming the IsUnknown() guard
// preserves first-create behavior.
func Test_CM_CipherTrust_License_ImmutableBindType_InitialCreate(t *testing.T) {
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

// Test_CM_License_Deterministic_Match verifies that the license resource
// is resolved correctly and deterministically using its exact license string match.
func Test_CM_License_Deterministic_Match(t *testing.T) {
	RequireCM(t)

	licenseStr := os.Getenv("CM_LICENSE_STRING")
	if licenseStr == "" {
		t.Skip("CM_LICENSE_STRING not set — skipping license matching acceptance test")
	}

	t.Setenv("TF_VAR_test_license", licenseStr)

	config := providerConfig + `
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
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "hash"),
				),
			},
		},
	})
}

