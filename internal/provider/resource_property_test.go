package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMProperty(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "ALLOW_UNKNOWN_FIELDS"
    value = "false"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "false"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "ALLOW_UNKNOWN_FIELDS"
    value = "true"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "true"),
				),
			},
			// Step 3: Attempt to rename — must fail at plan time with a clear error.
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name  = "ALLOW_UNKNOWN_FIELDS_RENAMED"
    value = "true"
}
`,
				ExpectError: regexp.MustCompile(`Name cannot be changed`),
				PlanOnly:    true,
			},
		},
		// Delete testing automatically occurs in TestCase
	})
}
