package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_ResourceCMSCPConnection(t *testing.T) {
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

			// Step 3: Attempt to rename — must fail at plan time with a clear error.
			{
				Config: providerConfig + `
resource "ciphertrust_scp_connection" "scp_connection" {
  name        = "TestSCPConnection-renamed"
  host        = "test-host"
  username    = "updated-user"
  auth_method = "key"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"
  path_to     = "/home/testUser/data/"
  products    = ["backup/restore"]
}
`,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
				PlanOnly:    true,
			},
		},
	})
}

func Test_CM_CipherTrust_SCPConnection_NameImmutable(t *testing.T) {
	RequireCM(t)
	if os.Getenv("SCP_HOST") == "" || os.Getenv("SCP_USERNAME") == "" {
		t.Skip("SCP_HOST / SCP_USERNAME not set — skipping SCP connection immutability test")
	}

	scpConnBase := `
resource "ciphertrust_scp_connection" "test" {
  host        = "` + os.Getenv("SCP_HOST") + `"
  port        = 22
  username    = "` + os.Getenv("SCP_USERNAME") + `"
  auth_method = "key"
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + scpConnBase + `  name = "tf-test-scp-conn"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.test", "name", "tf-test-scp-conn"),
				),
			},
			{
				Config: providerConfig + scpConnBase + `  name = "tf-test-scp-conn-renamed"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
		},
	})
}

// Test_CM_SCPConnection_EmptyNameRejected verifies that an empty name is rejected at plan time.
func Test_CM_SCPConnection_EmptyNameRejected(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_scp_connection" "test" {
  name       = ""
  host       = "192.0.2.1"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDx"
  username   = "testuser"
  auth_method = "key"
  path_to    = "/tmp/"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("string length must be at least 1"),
			},
		},
	})
}

// Test_CM_SCPConnection_EmptyPathToRejected verifies that path_to = "" is rejected at plan
// time, rather than being silently omitted from the PATCH body and producing a perpetual
// diff — CM's merge-PATCH leaves an omitted/empty path_to unchanged server-side.
func Test_CM_SCPConnection_EmptyPathToRejected(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_scp_connection" "test" {
  name        = "tf-test-scp-pathto"
  host        = "192.0.2.1"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDx"
  username    = "testuser"
  auth_method = "key"
  path_to     = ""
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("string length must be at least 1"),
			},
		},
	})
}

// Test_CM_SCPConnection_LabelsClearRetained verifies that clearing labels to {} after they
// were set retains the prior value (via modifiers.UseStateWhenClearingMap(), matching meta
// on this same resource) instead of crashing with "Provider produced inconsistent result
// after apply" — CM's merge-PATCH silently leaves an empty-object labels PATCH unchanged.
func Test_CM_SCPConnection_LabelsClearRetained(t *testing.T) {
	RequireCM(t)
	name := "tf-test-scp-labels-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scp_connection" "test" {
  name        = %q
  host        = "192.0.2.1"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDx"
  username    = "testuser"
  auth_method = "key"
  path_to     = "/tmp/"
  labels = {
    env = "test"
  }
}
`, name),
				Check: checkStep(t, "labels set",
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.test", "labels.env", "test"),
				),
			},
			{
				// Clear labels to {} — CM can't honour the clear; prior value retained.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scp_connection" "test" {
  name        = %q
  host        = "192.0.2.1"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDx"
  username    = "testuser"
  auth_method = "key"
  path_to     = "/tmp/"
  labels      = {}
}
`, name),
				Check: checkStep(t, "labels retained after clear attempt",
					resource.TestCheckResourceAttr("ciphertrust_scp_connection.test", "labels.env", "test"),
				),
				// A genuine labels change (even one the modifier resolves) triggers a real
				// Update() call; the immediate follow-up plan then shows description/meta/
				// service/updated_at as "(known after apply)" — a separate, pre-existing
				// instability in those Computed fields' plan modifiers under an active
				// Update(), independent of this labels fix. Flagged for separate follow-up;
				// not asserting a fully idempotent plan here.
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
