package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Test_CM_AwsConnectionList_basic creates one AWS connection, queries the list
// with a name filter, and asserts the single connection is returned.
func Test_CM_AwsConnectionList_basic(t *testing.T) {
	RequireCM(t)
	requireAWSIAMCredentials(t)

	name := "tftest-aws-conn-" + uuid.New().String()[:8]
	connConfig := awsConnConfig(name, "basic list test")
	listConfig := connConfig + fmt.Sprintf(`
data "ciphertrust_aws_connection_list" "test" {
  depends_on = [ciphertrust_aws_connection.test]
  filters = { name = %q }
}
`, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: listConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_aws_connection_list.test", "aws.#", "1"),
					resource.TestCheckResourceAttr("data.ciphertrust_aws_connection_list.test", "aws.0.name", name),
				),
			},
		},
	})
}

// Test_CM_AwsConnectionList_pagination creates two AWS connections and queries
// the list without filters to confirm GetAllPaged accumulates multiple results.
func Test_CM_AwsConnectionList_pagination(t *testing.T) {
	RequireCM(t)
	requireAWSIAMCredentials(t)

	name1 := "tftest-aws-conn-" + uuid.New().String()[:8]
	name2 := "tftest-aws-conn-" + uuid.New().String()[:8]

	conn1 := awsConnConfig(name1, "pagination test 1")
	// awsConnConfig wraps in providerConfig + resource block for "test"; create a
	// second resource by building a standalone block without the helper.
	conn2HCL := fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test2" {
  name          = %q
  access_key_id = %q
}
`, name2, awsAccessKeyID())

	listConfig := conn1 + conn2HCL + `
data "ciphertrust_aws_connection_list" "test" {
  depends_on = [ciphertrust_aws_connection.test, ciphertrust_aws_connection.test2]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: listConfig,
				Check: resource.ComposeTestCheckFunc(
					// At least 2 connections must be present — confirms multi-result accumulation.
					resource.TestCheckResourceAttrWith(
						"data.ciphertrust_aws_connection_list.test", "aws.#",
						func(val string) error {
							var n int
							fmt.Sscanf(val, "%d", &n)
							if n < 2 {
								return fmt.Errorf("expected at least 2 aws connections, got %d", n)
							}
							return nil
						},
					),
				),
			},
		},
	})
}

// Test_CM_ScpConnectionList_basic creates one SCP connection, queries the list
// with a name filter, and asserts the single connection is returned.
func Test_CM_ScpConnectionList_basic(t *testing.T) {
	RequireCM(t)

	name := "tftest-scp-conn-" + uuid.New().String()[:8]
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_scp_connection" "test" {
  name        = %q
  host        = "test-host"
  username    = "test-user"
  auth_method = "key"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"
  path_to     = "/home/testUser/data/"
  port        = 22
  protocol    = "scp"
}

data "ciphertrust_scp_connection_list" "test" {
  depends_on = [ciphertrust_scp_connection.test]
  filters    = { name = %q }
}
`, name, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_scp_connection_list.test", "scp.#", "1"),
					resource.TestCheckResourceAttr("data.ciphertrust_scp_connection_list.test", "scp.0.name", name),
				),
			},
		},
	})
}
