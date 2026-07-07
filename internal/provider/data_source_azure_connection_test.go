package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCiphertrustAzureConnectionDataSource(t *testing.T) {
	name := "test-azure-conn-" + uuid.New().String()[:8]

	// On CDSPaaS the labels query-parameter format ("key=value" string) is not
	// accepted — the API returns a metaContains JSON parse error. Use the name
	// filter instead. On CM the original label-based filter is preserved.
	var filterBlock string
	if os.Getenv(envCDSPaaS) == "true" {
		filterBlock = fmt.Sprintf("name = %q", name)
	} else {
		filterBlock = `labels = "environment=devenv"`
	}

	azureConnectionConfig := fmt.Sprintf(`
resource "ciphertrust_azure_connection" "azure_connection" {
  name          = %q
  products      = ["cckm"]
  client_secret = "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name    = "AzureCloud"
  client_id     = "3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id     = "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  description   = "connection description"
  labels = {
    "environment" = "devenv"
  }
}

data "ciphertrust_azure_connection_list" "azure_connection_details" {
  depends_on = [ciphertrust_azure_connection.azure_connection]
  filters = {
    %s
  }
}
`, name, filterBlock)

	datasourceName := "data.ciphertrust_azure_connection_list.azure_connection_details"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + azureConnectionConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_azure_connection.azure_connection", "id"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.name", name),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.tenant_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.description", "connection description"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.cloud_name", "AzureCloud"),
					resource.TestCheckResourceAttr(datasourceName, "azure.0.client_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"),
				),
			},
		},
	})
}
