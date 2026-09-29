package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmAzureVaultDetails tests the ciphertrust_azure_vault_details data source.
// It is skipped when the Azure environment variables are not set.
//
// The success step chains ciphertrust_azure_subscription_details to pick the first
// subscription returned by the connection, avoiding a separate env var for the
// subscription ID.
func TestCckmAzureVaultDetails(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureVaultDetails")
	}

	t.Run("success", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					// List subscriptions live from Azure first, then use subscriptions[0]
					// as the subscription_id for the vault details datasource.
					Config: initConfig + `
					data "ciphertrust_azure_subscription_details" "subs" {
						connection_id = ciphertrust_azure_connection.azure_connection.id
					}
					data "ciphertrust_azure_vault_details" "test" {
						connection_id   = ciphertrust_azure_connection.azure_connection.id
						subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
					}`,
					Check: resource.ComposeTestCheckFunc(
						// vaults.% is the map size attribute - confirms the API was called
						// and at least one vault entry was written to state.
						resource.TestCheckResourceAttrSet(
							"data.ciphertrust_azure_vault_details.test",
							"vaults.%",
						),
					),
				},
			},
		})
	})

	t.Run("managed_hsm", func(t *testing.T) {
		if os.Getenv("CCKM_TF_AZURE_PREMIUM_VAULT") == "" {
			t.Skip("CCKM_TF_AZURE_PREMIUM_VAULT not set - skipping managed_hsm sub-test")
		}
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: initConfig + `
					data "ciphertrust_azure_subscription_details" "subs" {
						connection_id = ciphertrust_azure_connection.azure_connection.id
					}
					data "ciphertrust_azure_vault_details" "hsm" {
						connection_id   = ciphertrust_azure_connection.azure_connection.id
						subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
						managed_hsms    = true
					}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(
							"data.ciphertrust_azure_vault_details.hsm",
							"vaults.%",
						),
					),
				},
			},
		})
	})

	t.Run("failure", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					// A connection name that does not exist must produce an error.
					Config: fmt.Sprintf(`
						data "ciphertrust_azure_vault_details" "test" {
							connection_id   = "this-connection-does-not-exist"
							subscription_id = "%s"
						}`, "00000000-0000-0000-0000-000000000000"),
					ExpectError: regexp.MustCompile(`Error reading Azure vault details`),
				},
			},
		})
	})
}
