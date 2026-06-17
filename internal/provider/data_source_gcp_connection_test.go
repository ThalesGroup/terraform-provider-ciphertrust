package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestGCPConnectionDataSource(t *testing.T) {
	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("Failed to set GCP connection variables")
	}

	name := "test-gcp-conn-" + uuid.New().String()[:8]

	// On CDSPaaS the labels query-parameter format is not accepted.
	// Use the name filter instead; on CM the original label filter is preserved.
	var filterBlock string
	if os.Getenv(envCDSPaaS) == "true" {
		filterBlock = fmt.Sprintf("name = %q", name)
	} else {
		filterBlock = `labels = "environment=test"`
	}

	gcpConnectionConfig := fmt.Sprintf(`
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name        = %q
  products    = ["cckm"]
  key_file    = <<-EOT
    %s
  EOT
  cloud_name  = "gcp"
  description = "connection description"
  labels = {
    "environment" = "test"
  }
}

data "ciphertrust_gcp_connection_list" "gcp_connection_details" {
  depends_on = [ciphertrust_gcp_connection.gcp_connection]
  filters = {
    %s
  }
}
`, name, gcpKeyFile, filterBlock)

	datasourceName := "data.ciphertrust_gcp_connection_list.gcp_connection_details"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + gcpConnectionConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "id"),
					resource.TestCheckResourceAttr(datasourceName, "gcp.0.name", name),
					resource.TestCheckResourceAttr(datasourceName, "gcp.0.cloud_name", "gcp"),
					resource.TestCheckResourceAttrSet(datasourceName, "gcp.0.private_key_id"),
					resource.TestCheckResourceAttrSet(datasourceName, "gcp.0.client_email"),
					resource.TestCheckResourceAttr(datasourceName, "gcp.0.description", "connection description"),
				),
			},
		},
	})
}
