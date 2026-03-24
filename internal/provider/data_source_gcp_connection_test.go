package provider

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"os"
	"testing"
)

func TestGCPConnectionDataSource(t *testing.T) {
	// Config for the resource and data source
	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("Failed to set GCP connection variables")
	}

	gcpConnectionConfig := `
		resource "ciphertrust_gcp_connection" "gcp_connection" {
			name = "test-gcp-connection"
			products = [
				"%s"
			]
			key_file    = <<-EOT
				%s
			EOT
			cloud_name  = "gcp"
			description = "connection description"
			labels = {
				"environment" = "test"
			}
			meta = {
				"custom_meta_key1"   = "custom_value1"
				"customer_meta_key2" = "custom_value2"
			}
		}
		
		# Data source to retrieve the GCP connection
		data "ciphertrust_gcp_connection_list" "gcp_connection_details" {
		depends_on = [ciphertrust_gcp_connection.gcp_connection]
		   filters = {
   			 labels = "environment=test"
  			}
		}`

	//Name of the data source to check
	datasourceName := "data.ciphertrust_gcp_connection_list.gcp_connection_details"

	// Running the test case
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Config to apply the resource and data source
				Config: providerConfig + fmt.Sprintf(gcpConnectionConfig, gcpKeyFile),
				Check: resource.ComposeTestCheckFunc(
					// Ensure the resource was created first
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "id"),

					resource.TestCheckResourceAttr(datasourceName, "gcp.0.name", "test-gcp-connection"),
					resource.TestCheckResourceAttr(datasourceName, "gcp.0.cloud_name", "gcp"),
					resource.TestCheckResourceAttrSet(datasourceName, "gcp.0.private_key_id"),
					resource.TestCheckResourceAttrSet(datasourceName, "gcp.0.client_email"),
					resource.TestCheckResourceAttr(datasourceName, "gcp.0.description", "connection description"),
				),
			},
		},
	})
}
