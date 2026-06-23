package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceGCPConnection(t *testing.T) {
	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("Failed to set GCP connection variables")
	}

	name := "test-gcp-conn-" + uuid.New().String()[:8]

	// On CDSPaaS the "ddc" product is not supported for GCP connections (422).
	// Use "cckm" for both steps on CDSPaaS and still verify the update by
	// changing the description. On CM use "ddc" as originally intended.
	updateProduct := "ddc"
	if os.Getenv(envCDSPaaS) == "true" {
		updateProduct = "cckm"
	}

	createResourcesConfig := `
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name = %q
  products = [%q]
  key_file    = <<-EOT
    %s
  EOT
  cloud_name  = "gcp"
  description = %q
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1"   = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }
}`

	createConfig := fmt.Sprintf(createResourcesConfig, name, "cckm", gcpKeyFile, "connection description")
	updateConfig := fmt.Sprintf(createResourcesConfig, name, updateProduct, gcpKeyFile, "updated connection description")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + createConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "private_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "client_email"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "cloud_name", "gcp"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", "cckm"),
				),
			},

		// Step 2: Update — product and description
		{
			Config: providerConfig + updateConfig,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "private_key_id"),
				resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "client_email"),
				resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "description", "updated connection description"),
				resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
				resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", updateProduct),
			),
		},

		// Step 3: Attempt to rename — must fail at plan time with a clear error.
		{
			Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name     = "test-gcp-connection-renamed"
  key_file = <<-EOT
    %s
  EOT
}
`, gcpKeyFile),
			ExpectError: regexp.MustCompile(`Connection name cannot be changed`),
			PlanOnly:    true,
		},
	},
	})
}

// terraform destroy will perform automatically at the end of the test
