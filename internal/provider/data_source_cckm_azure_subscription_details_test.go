package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// initCckmAzureTestWithoutVault builds the Terraform provider and connection configuration used as
// shared setup by CCKM Azure tests. The four core variables
// (CCKM_TF_AZURE_CLIENT_ID, CCKM_TF_AZURE_TENANT_ID, CCKM_TF_AZURE_CLIENT_SECRET,
// CCKM_TF_AZURE_STANDARD_VAULT) must be set; if any are missing the function returns
// an empty string and false and the caller should call t.Skip().
// CCKM_TF_AZURE_PREMIUM_VAULT is optional and is only required by tests that use a
// premium (HSM-backed) vault - those tests must perform their own skip check.
// The optional timeout parameter is accepted for API consistency with initCckmAwsTest.
func initCckmAzureTestWithoutVault(timeout ...int) (string, bool) {
	clientID := os.Getenv("CCKM_TF_AZURE_CLIENT_ID")
	tenantID := os.Getenv("CCKM_TF_AZURE_TENANT_ID")
	clientSecret := os.Getenv("CCKM_TF_AZURE_CLIENT_SECRET")
	standardVault := os.Getenv("CCKM_TF_AZURE_STANDARD_VAULT")
	// premiumVault is optional - only required by tests that specifically need a
	// premium (HSM-backed) vault. Those tests must call
	// t.Skip if CCKM_TF_AZURE_PREMIUM_VAULT is empty.
	premiumVault := os.Getenv("CCKM_TF_AZURE_PREMIUM_VAULT")

	if clientID == "" || tenantID == "" || clientSecret == "" || standardVault == "" {
		return "", false
	}

	// Honour CIPHERTRUST_CA_CERT when set; otherwise opt into skip-verify so the
	// inline test provider block is not blocked by secure-by-default TLS behaviour.
	tlsLine := "  no_ssl_verify = true"
	if caCert := os.Getenv("CIPHERTRUST_CA_CERT"); caCert != "" {
		tlsLine = fmt.Sprintf("  ca_cert = %q", caCert)
	}

	uid := "tf-" + uuid.New().String()[:8]
	config := `
		provider "ciphertrust" {
` + tlsLine + `
		}
		resource "ciphertrust_azure_connection" "azure_connection" {
			name          = "%s"
			client_id     = "%s"
			tenant_id     = "%s"
			client_secret = "%s"
			cloud_name    = "AzureCloud"
			products      = ["cckm"]
		}
		locals {
			azure_standard_vault = "%s"
			azure_premium_vault  = "%s"
		}`
	return fmt.Sprintf(config, uid, clientID, tenantID, clientSecret, standardVault, premiumVault), true
}

// TestCckmAzureSubscriptionDetails tests the ciphertrust_azure_subscription_details data source.
// It is skipped when the Azure environment variables are not set.
func TestCckmAzureDataSourceSubscriptionDetails(t *testing.T) {
	initConfig, ok := initCckmAzureTestWithoutVault()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureSubscriptionDetails")
	}

	t.Run("success", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					// A valid connection name must return at least one subscription.
					Config: initConfig + `
					data "ciphertrust_azure_subscription_details" "test" {
						connection_id = ciphertrust_azure_connection.azure_connection.id
					}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(
							"data.ciphertrust_azure_subscription_details.test",
							"subscriptions.0.subscription_id",
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
					Config: `
					data "ciphertrust_azure_subscription_details" "test" {
						connection_id = "this-connection-does-not-exist"
					}`,
					ExpectError: regexp.MustCompile(`Error reading Azure subscription details`),
				},
			},
		})
	})
}
