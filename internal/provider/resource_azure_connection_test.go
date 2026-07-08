package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceAzureConnection(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// creating a Azure connection
			{
				Config: providerConfig + `
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "TestAzureConnection"
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name= "AzureCloud"
  products = [
    "cckm"
  ]
  description = "a description of the connection"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"  # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2"  # Another custom metadata entry
  }
}
`,

				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_azure_connection.azure_connection", "id"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "name", "TestAzureConnection"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "tenant_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "description", "a description of the connection"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "client_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"),
				),
			},

		// Step 2: Update the resource
		{
			Config: providerConfig + `
resource "ciphertrust_azure_connection" "azure_connection" {
  name        = "TestAzureConnection"
  client_id="updated-client-id"
  tenant_id= "updated-tenant-id"
  products = [
    "cckm"
  ]
  description = "updated description of the connection"
  
}
			`,

			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "tenant_id", "updated-tenant-id"),
				resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "description", "updated description of the connection"),
				resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "client_id", "updated-client-id"),
			),
		},

		// Step 3: Attempt to rename — must fail at plan time with a clear error.
		{
			Config: providerConfig + `
resource "ciphertrust_azure_connection" "azure_connection" {
  name      = "TestAzureConnection-renamed"
  client_id = "updated-client-id"
  tenant_id = "updated-tenant-id"
  products  = ["cckm"]
}
`,
			ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			PlanOnly:    true,
		},
	},
	})
}

func TestCipherTrust_AzureConnection_NameImmutable(t *testing.T) {
	RequireCM(t)
	if os.Getenv("AZURE_CLIENT_ID") == "" || os.Getenv("AZURE_TENANT_ID") == "" || os.Getenv("AZURE_CLIENT_SECRET") == "" {
		t.Skip("AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET not set — skipping Azure connection immutability test")
	}
	t.Setenv("TF_VAR_azure_client_secret", os.Getenv("AZURE_CLIENT_SECRET"))

	azureConnBase := fmt.Sprintf(`
variable "azure_client_secret" { sensitive = true }
resource "ciphertrust_azure_connection" "test" {
  client_id     = %q
  tenant_id     = %q
  client_secret = var.azure_client_secret
`, os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_TENANT_ID"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + azureConnBase + `  name = "tf-test-azure-conn"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.test", "name", "tf-test-azure-conn"),
				),
			},
			{
				Config: providerConfig + azureConnBase + `  name = "tf-test-azure-conn-renamed"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
