package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceAzureConnection(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// creating a Azure connection
			{
				Config: providerConfig + `
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "TestAzureConnection"
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name= "AzureCloud"
  products = [
    "cckm"
  ]
  description = "a description of the connection"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"  # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2"  # Another custom metadata entry
  }
}
`,

				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_azure_connection.azure_connection", "id"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "name", "TestAzureConnection"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "tenant_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "description", "a description of the connection"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "client_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + `
resource "ciphertrust_azure_connection" "azure_connection" {
  name        = "TestAzureConnection"
  client_id="updated-client-id"
  tenant_id= "updated-tenant-id"
  products = [
    "cckm"
  ]
  description = "updated description of the connection"
  
}
				`,

				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "tenant_id", "updated-tenant-id"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "description", "updated description of the connection"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "client_id", "updated-client-id"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
