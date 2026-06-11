package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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

const gcpConnectionResourceName = "ciphertrust_gcp_connection.gcp_conn_oob"

func gcpConnectionOOBConfig(name, keyFile string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_gcp_connection" "gcp_conn_oob" {
  name       = %q
  key_file   = %q
  cloud_name = "gcp"
}
`, name, keyFile)
}

func TestAccGCPConnection_OOBDelete(t *testing.T) {
	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("CCKM_GOOGLE_KEY_FILE not set")
	}

	var capturedID string
	connName := "TFTestGCPConnOOB"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: gcpConnectionOOBConfig(connName, gcpKeyFile),
				Check: checkStep(t, "oob delete: create",
					resource.TestCheckResourceAttrSet(gcpConnectionResourceName, "id"),
					resource.TestCheckResourceAttr(gcpConnectionResourceName, "name", connName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[gcpConnectionResourceName]
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
						common.URL_GCP_CONNECTION+"/"+capturedID,
					)
				},
				Config:             gcpConnectionOOBConfig(connName, gcpKeyFile),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccGCPConnection_DeleteOOBThenDestroy(t *testing.T) {
	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("CCKM_GOOGLE_KEY_FILE not set")
	}

	var capturedID string
	connName := "TFTestGCPConnOOBDestroy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: gcpConnectionOOBConfig(connName, gcpKeyFile),
				Check: checkStep(t, "oob destroy: create",
					resource.TestCheckResourceAttrSet(gcpConnectionResourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[gcpConnectionResourceName]
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
						common.URL_GCP_CONNECTION+"/"+capturedID,
					)
				},
				Config:  gcpConnectionOOBConfig(connName, gcpKeyFile),
				Destroy: true,
			},
		},
	})
}
