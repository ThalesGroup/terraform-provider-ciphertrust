package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMSCPConnection(t *testing.T) {
	RequireCM(t)
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

const scpConnectionResourceName = "ciphertrust_scp_connection.scp_conn_oob"

const scpTestPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"

func scpConnectionOOBConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scp_connection" "scp_conn_oob" {
  name        = %q
  host        = "test-host"
  username    = "test-user"
  auth_method = "key"
  public_key  = %q
  path_to     = "/home/testUser/data/"
  products    = ["backup/restore"]
}
`, name, scpTestPublicKey)
}

func TestAccSCPConnection_OOBDelete(t *testing.T) {
	var capturedID string
	connName := "TFTestSCPConnOOB"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scpConnectionOOBConfig(connName),
				Check: checkStep(t, "oob delete: create",
					resource.TestCheckResourceAttrSet(scpConnectionResourceName, "id"),
					resource.TestCheckResourceAttr(scpConnectionResourceName, "name", connName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[scpConnectionResourceName]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion; Read() should remove from state and next plan proposes re-create.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_SCP_CONNECTION+"/"+capturedID,
					)
				},
				Config:             scpConnectionOOBConfig(connName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccSCPConnection_DeleteOOBThenDestroy(t *testing.T) {
	var capturedID string
	connName := "TFTestSCPConnOOBDestroy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scpConnectionOOBConfig(connName),
				Check: checkStep(t, "oob destroy: create",
					resource.TestCheckResourceAttrSet(scpConnectionResourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[scpConnectionResourceName]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion followed by terraform destroy: Delete() 404 guard must suppress error.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_SCP_CONNECTION+"/"+capturedID,
					)
				},
				Config:  scpConnectionOOBConfig(connName),
				Destroy: true,
			},
		},
	})
}
