package provider

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"os"
	"testing"
)

func TestResourceGCPConnection(t *testing.T) {

	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("Failed to set GCP connection variables")
	}

	createResourcesConfig := `
		resource "ciphertrust_gcp_connection" "gcp_connection" {
			name = "test-gcp-connection"
			products = [
				"%s"
			]
			key_file    = <<-EOT
				%s
			EOT
			cloud_name  = "gcp"
			description = "%s"
			labels = {
				"environment" = "devenv"
			}
			meta = {
				"custom_meta_key1"   = "custom_value1"
				"customer_meta_key2" = "custom_value2"
			}
		}`

	createConfig := fmt.Sprintf(createResourcesConfig, "cckm", gcpKeyFile, "connection description")
	updateConfig := fmt.Sprintf(createResourcesConfig, "ddc", gcpKeyFile, "updated connection description")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// creating a GCP connection
				Config: providerConfig + createConfig,
				// verifying the resources for id, private key id, client email, cloud name and products
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccListResourceAttributes("ciphertrust_gcp_connection.gcp_connection"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "private_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "client_email"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "cloud_name", "gcp"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", "cckm"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + updateConfig,
				// verifying the updated field private key id, client email, description and products
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "private_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "client_email"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "description", "updated connection description"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", "ddc"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
