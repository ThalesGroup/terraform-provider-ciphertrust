package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMSCPConnection(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// creating an SCP connection
			{
				Config: providerConfig + `
resource "ciphertrust_scp_connection" "scp_connection" {
  name        = "TestSCPConnection"
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
`,
				// verifying the resources for id, authmethod, protocol and port
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scp_connection.scp_connection", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.scp_connection", "auth_method", "key"),
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.scp_connection", "protocol", "scp"),
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.scp_connection", "port", "22"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + `
resource "ciphertrust_scp_connection" "scp_connection" {
  name        = "TestSCPConnection"
  host        = "test-host"
  username    = "updated-user"
  auth_method = "key"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"
  path_to     = "/home/testUser/data/"
  port        = 2022
  protocol    = "sftp"
  labels = {
    "environment" = "test"
    "department"  = "IT"
  }
  products = ["backup/restore"]
}
				`,
				// verifying the updated field username,port and protocol
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.scp_connection", "protocol", "sftp"),
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.scp_connection", "port", "2022"),
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.scp_connection", "username", "updated-user"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
