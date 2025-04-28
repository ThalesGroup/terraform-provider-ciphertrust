package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMProperty(t *testing.T) {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	bootstrap := "no"

	if address == "" || username == "" || password == "" {
		t.Fatal("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, and CIPHERTRUST_PASSWORD must be set for testing")
	}

	providerConfig := fmt.Sprintf(providerConfig, address, username, password, bootstrap)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "ENABLE_RECORDS_DB_STORE"
    value = "false"
	description = "Store audit records in database. Disabling also deletes the audit records. Values: true or false"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "name", "ENABLE_RECORDS_DB_STORE"),
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "false"),
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "description", "Store audit records in database. Disabling also deletes the audit records. Values: true or false"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "ENABLE_RECORDS_DB_STORE"
    value = "true"
	description = "Store audit records in database. Disabling also deletes the audit records. Values: true or false"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "name", "ENABLE_RECORDS_DB_STORE"),
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "true"),
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "description", "Store audit records in database. Disabling also deletes the audit records. Values: true or false"),
				),
			},
		},
		// Delete testing automatically occurs in TestCase
	})
}
