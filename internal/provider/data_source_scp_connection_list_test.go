package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// scpConnConfig generates HCL for a single ciphertrust_scp_connection resource
// with a unique label derived from idx, plus a minimal valid configuration.
func scpConnConfig(idx int, name, host, username string) string {
	return fmt.Sprintf(`
resource "ciphertrust_scp_connection" "conn%d" {
  name        = %q
  host        = %q
  username    = %q
  auth_method = "key"
  public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"
}
`, idx, name, host, username)
}

// scpConnListConfig generates HCL for n distinct ciphertrust_scp_connection resources
// plus a ciphertrust_scp_connection_list data source block.
func scpConnListConfig(namePrefix, host, username string, count int, filters string) string {
	cfg := providerConfig
	for i := 0; i < count; i++ {
		cfg += scpConnConfig(i, fmt.Sprintf("%s-%d", namePrefix, i), host, username)
	}

	// Build depends_on from all connection resource references.
	deps := ""
	for i := 0; i < count; i++ {
		if i > 0 {
			deps += ", "
		}
		deps += fmt.Sprintf("ciphertrust_scp_connection.conn%d", i)
	}

	if filters == "" {
		cfg += fmt.Sprintf(`
data "ciphertrust_scp_connection_list" "all" {
  depends_on = [%s]
}
`, deps)
	} else {
		cfg += fmt.Sprintf(`
data "ciphertrust_scp_connection_list" "all" {
  depends_on = [%s]
  filters = {
    %s
  }
}
`, deps, filters)
	}
	return cfg
}

// TestCckmScpConnectionList_pagination verifies that ciphertrust_scp_connection_list
// returns all connections when more than one page (> 10) exist on CM.
func TestCckmScpConnectionList_pagination(t *testing.T) {
	RequireCM(t)
	if os.Getenv("SCP_HOST") == "" || os.Getenv("SCP_USERNAME") == "" {
		t.Skip("SCP_HOST and SCP_USERNAME must be set for this test")
	}

	host := os.Getenv("SCP_HOST")
	username := os.Getenv("SCP_USERNAME")
	namePrefix := "tftest-scplist-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scpConnListConfig(namePrefix, host, username, 12, ""),
				Check: resource.TestCheckResourceAttr(
					"data.ciphertrust_scp_connection_list.all", "scp.#", "12",
				),
			},
		},
	})
}

// TestCckmScpConnectionList_singlePage verifies that passing skip/limit in filters
// invokes the single-page branch and returns exactly the requested count.
func TestCckmScpConnectionList_singlePage(t *testing.T) {
	RequireCM(t)
	if os.Getenv("SCP_HOST") == "" || os.Getenv("SCP_USERNAME") == "" {
		t.Skip("SCP_HOST and SCP_USERNAME must be set for this test")
	}

	host := os.Getenv("SCP_HOST")
	username := os.Getenv("SCP_USERNAME")
	namePrefix := "tftest-scplist-sp-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: scpConnListConfig(namePrefix, host, username, 3, `skip = "0"
    limit = "1"`),
				Check: resource.TestCheckResourceAttr(
					"data.ciphertrust_scp_connection_list.all", "scp.#", "1",
				),
			},
		},
	})
}
