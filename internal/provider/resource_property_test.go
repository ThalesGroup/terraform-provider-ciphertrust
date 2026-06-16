package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCMProperty_RenameError(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ALLOW_UNKNOWN_FIELDS"
  value = "false"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "name", "ALLOW_UNKNOWN_FIELDS"),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ALLOW_UNKNOWN_FIELDS_RENAMED"
  value = "false"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Attribute 'name' cannot be changed after creation"),
			},
		},
	})
}

func TestAccCMProperty_UpdateInPlace(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ALLOW_UNKNOWN_FIELDS"
  value = "false"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "false"),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ALLOW_UNKNOWN_FIELDS"
  value = "true"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "true"),
					resource.TestCheckResourceAttr("ciphertrust_property.test", "name", "ALLOW_UNKNOWN_FIELDS"),
				),
			},
		},
	})
}

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
				)},
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
		},
		// Delete testing automatically occurs in TestCase
	})
}
