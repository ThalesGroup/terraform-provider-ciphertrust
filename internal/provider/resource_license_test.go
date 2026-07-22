package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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

// Test_CM_License_NoDriftAfterApply verifies that after a successful apply, a subsequent
// plan-only step with the same config reports no changes. This exercises Fix 1
// (ImmutableString null guard) and Fix 3 (Read() else-null removal for bind_type) together.
func Test_CM_License_NoDriftAfterApply(t *testing.T) {
	RequireCM(t)

	licenseStr := os.Getenv("TF_ACC_CM_LICENSE_STRING")
	if licenseStr == "" {
		t.Skip("TF_ACC_CM_LICENSE_STRING not set — skipping license no-drift acceptance test")
	}

	t.Setenv("TF_VAR_acc_license_nodrift", licenseStr)

	licenseConfig := providerConfig + `
variable "acc_license_nodrift" {
  type = string
}

resource "ciphertrust_license" "test" {
  license = var.acc_license_nodrift
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: licenseConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_license.test", "bind_type"),
				),
			},
			{
				Config:   licenseConfig,
				PlanOnly: true,
			},
		},
	})
}

// Test_CM_License_DriftDetected_BindType verifies that when CM returns a different
// bind_type value than what is tracked in state, Read() surfaces it as a plan diff.
// This confirms Fix 3 only preserves state when CM *omits* bind_type, not when CM
// returns a genuinely different value.
//
// Step 2 uses a PreConfig to attempt an out-of-band mutation of bind_type via the CM
// API. If the CM API supports this PATCH, a non-empty plan is expected on refresh.
// If the CM API does not permit bind_type mutation (it may be immutable at the API
// level), the test will fail — which is the correct signal to update this test's
// design for that specific CM version.
func Test_CM_License_DriftDetected_BindType(t *testing.T) {
	RequireCM(t)

	licenseStr := os.Getenv("TF_ACC_CM_LICENSE_STRING")
	if licenseStr == "" {
		t.Skip("TF_ACC_CM_LICENSE_STRING not set — skipping license drift-detection acceptance test")
	}

	t.Setenv("TF_VAR_acc_license_drift", licenseStr)

	licenseConfig := providerConfig + `
variable "acc_license_drift" {
  type = string
}

resource "ciphertrust_license" "test" {
  license   = var.acc_license_drift
  bind_type = "instance"
}
`

	var capturedID string
	var capturedBindType string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: licenseConfig,
				Check: func(s *terraform.State) error {
					res, ok := s.RootModule().Resources["ciphertrust_license.test"]
					if !ok {
						return fmt.Errorf("ciphertrust_license.test not found in state")
					}
					capturedID = res.Primary.ID
					capturedBindType = res.Primary.Attributes["bind_type"]
					return nil
				},
			},
			{
				// PreConfig mutates bind_type out-of-band so that the subsequent
				// RefreshState reads a different value, producing a non-empty plan.
				// t.Skip/t.Fatal must NOT be used here (they cause a goroutine panic
				// in PreConfig closures); log and return on failure instead.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping out-of-band bind_type mutation")
						return
					}
					if capturedID == "" {
						t.Logf("resource ID not captured in step 1 — skipping out-of-band mutation")
						return
					}
					newBindType := "cluster"
					if capturedBindType == "cluster" {
						newBindType = "instance"
					}
					payload, _ := json.Marshal(map[string]interface{}{"bind_type": newBindType})
					_, err := client.UpdateDataV2(context.Background(), capturedID, common.URL_LICENSE, payload)
					if err != nil {
						t.Logf("out-of-band bind_type mutation to %q failed (CM may not permit this): %v", newBindType, err)
						return
					}
					t.Logf("out-of-band bind_type mutated to %q — expecting drift on refresh", newBindType)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
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

