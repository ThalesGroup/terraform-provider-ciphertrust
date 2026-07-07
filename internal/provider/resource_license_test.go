package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccCMLicense_ComputedFields verifies that all stable Computed-only fields are
// populated after create and produce no drift on subsequent refresh.
func TestAccCMLicense_ComputedFields(t *testing.T) {
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
