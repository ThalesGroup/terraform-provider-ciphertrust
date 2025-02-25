package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCiphertrustSCPConnectionDataSource(t *testing.T) {
	// Config for the resource and data source
	scpConnectionConfig := `
		// Resource configuration for the SCP connection
		resource "ciphertrust_scp_connection" "scp_connection" {
		  name        = "TestSCPConnection1"
		  host        = "test-host"
		  username    = "test-user"
		  auth_method = "key"
		  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"
		  path_to     = "/home/testUser/data/"
		  port        = 22
		  protocol    = "scp"
		  labels = {
		    "environment" = "test"
		    "department"  = "IT"
		  }
		  products = ["backup/restore"]
		}
		
		// Data source to retrieve the SCP connection
		data "ciphertrust_scp_connection_list" "scp_connection_details" {
		depends_on = [ciphertrust_scp_connection.scp_connection]
		   filters = {
   			 labels = "environment=test"
  			}
		}`

	//Name of the data source to check
	datasourceName := "data.ciphertrust_scp_connection_list.scp_connection_details"

	// Running the test case
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Config to apply the resource and data source
				Config: providerConfig + scpConnectionConfig,
				Check: resource.ComposeTestCheckFunc(
					// Ensure the resource was created first
					resource.TestCheckResourceAttrSet("ciphertrust_scp_connection.scp_connection", "id"),

					resource.TestCheckResourceAttr(datasourceName, "scp.0.name", "TestSCPConnection1"),
					resource.TestCheckResourceAttr(datasourceName, "scp.0.host", "test-host"),
					resource.TestCheckResourceAttr(datasourceName, "scp.0.username", "test-user"),
					resource.TestCheckResourceAttr(datasourceName, "scp.0.path_to", "/home/testUser/data/"),
					resource.TestCheckResourceAttr(datasourceName, "scp.0.port", "22"),
					resource.TestCheckResourceAttr(datasourceName, "scp.0.protocol", "scp"),
				),
			},
		},
	})
}
