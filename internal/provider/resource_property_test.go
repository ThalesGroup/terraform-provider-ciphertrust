package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMProperty(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "HIDE_COMPOSITE_KEY"
    value = "false"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "false"),
				)},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "HIDE_COMPOSITE_KEY"
    value = "true"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "true"),
				),
			},
		},
		// Delete testing automatically occurs in TestCase
	})
}
