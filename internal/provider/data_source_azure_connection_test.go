//go:build skip

package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCiphertrustAzureConnectionDataSource(t *testing.T) {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	bootstrap := "no"

	if address == "" || username == "" || password == "" {
		t.Fatal("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, and CIPHERTRUST_PASSWORD must be set for testing")
	}

	providerConfig := fmt.Sprintf(providerConfig, address, username, password, bootstrap)

	// Config for the resource and data source
	azureConnectionConfig := `
		// Resource configuration for the Azure connection
		resource "ciphertrust_azure_connection" "azure_connection" {
         name        = "test-azure-connection"
         products = [
			"cckm"
		]
		client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
		cloud_name= "AzureCloud"
		client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
		tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
		description = "connection description"
		  labels = {
			"environment" = "devenv"
		  }
		}

		// Data source to retrieve the Azure connection
		data "ciphertrust_azure_connection_list" "azure_connection_details" {
		depends_on = [ciphertrust_azure_connection.azure_connection]
		   filters = {
   			 labels = "environment=devenv"
			}
		}`

	//Name of the data source to check
	datasourceName := "data.ciphertrust_azure_connection_list.azure_connection_details"

	// Running the test case
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Config to apply the resource and data source
				Config: providerConfig + azureConnectionConfig,
				Check: resource.ComposeTestCheckFunc(
					// Ensure the resource was created first
					resource.TestCheckResourceAttrSet("ciphertrust_azure_connection.azure_connection", "id"),

					resource.TestCheckResourceAttr(datasourceName, "azure.0.name", "test-azure-connection"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.tenant_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.description", "connection description"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.cloud_name", "AzureCloud"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.client_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"),
				),
			},
		},
	})
}
