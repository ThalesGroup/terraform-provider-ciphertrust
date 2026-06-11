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
		},
	})
}

// terraform destroy will perform automatically at the end of the test

const azureConnectionResourceName = "ciphertrust_azure_connection.azure_conn_oob"

func azureConnectionOOBConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_connection" "azure_conn_oob" {
  name          = %q
  client_id     = "3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id     = "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  client_secret = "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name    = "AzureCloud"
}
`, name)
}

func TestAccAzureConnection_OOBDelete(t *testing.T) {
	var capturedID string
	connName := "TFTestAzureConnOOB"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: azureConnectionOOBConfig(connName),
				Check: checkStep(t, "oob delete: create",
					resource.TestCheckResourceAttrSet(azureConnectionResourceName, "id"),
					resource.TestCheckResourceAttr(azureConnectionResourceName, "name", connName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[azureConnectionResourceName]
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
						common.URL_AZURE_CONNECTION+"/"+capturedID,
					)
				},
				Config:             azureConnectionOOBConfig(connName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccAzureConnection_DeleteOOBThenDestroy(t *testing.T) {
	var capturedID string
	connName := "TFTestAzureConnOOBDestroy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: azureConnectionOOBConfig(connName),
				Check: checkStep(t, "oob destroy: create",
					resource.TestCheckResourceAttrSet(azureConnectionResourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[azureConnectionResourceName]
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
						common.URL_AZURE_CONNECTION+"/"+capturedID,
					)
				},
				Config:  azureConnectionOOBConfig(connName),
				Destroy: true,
			},
		},
	})
}
