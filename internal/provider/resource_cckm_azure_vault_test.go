package provider

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/tidwall/gjson"
)

// cleanupCckmAzureVaults removes the standard and premium Azure vaults (CCKM_TF_AZURE_STANDARD_VAULT
// and CCKM_TF_AZURE_PREMIUM_VAULT) from CipherTrust Manager if a previous failed test run left them
// behind. The same vault cannot be added twice, so a leftover would break the next run. Only vaults
// whose azure_name matches one of the two env vars are removed. The vaults are removed from CM only,
// nothing is deleted in Azure. Only runs when TF_CCKM_CLEANUP=true is set. All errors are logged as
// warnings - the cleanup is best-effort and never fails the test.
func cleanupCckmAzureVaults() {
	if os.Getenv("TF_CCKM_CLEANUP") != "true" {
		return
	}
	names := map[string]bool{}
	for _, envVar := range []string{"CCKM_TF_AZURE_STANDARD_VAULT", "CCKM_TF_AZURE_PREMIUM_VAULT"} {
		if name := os.Getenv(envVar); name != "" {
			names[name] = true
		}
	}
	if len(names) == 0 {
		return
	}
	client, ok := createCMClient()
	if !ok {
		fmt.Println("cleanupCckmAzureVaults: could not create CM client, skipping cleanup")
		return
	}
	ctx := context.Background()
	filters := url.Values{}
	filters.Add("limit", "1000")
	response, err := client.ListWithFilters(ctx, uuid.NewString(), common.URL_AZURE+"/vaults", filters)
	if err != nil {
		fmt.Printf("** cleanupCckmAzureVaults: failed to list vaults: %s\n", err.Error())
		return
	}
	for _, r := range gjson.Get(response, "resources").Array() {
		azureName := gjson.Get(r.Raw, "azure_name").String()
		if !names[azureName] {
			continue
		}
		vaultID := gjson.Get(r.Raw, "id").String()
		_, err := client.PostNoData(ctx, uuid.NewString(), common.URL_AZURE+"/vaults/"+vaultID+"/remove-vault")
		if err != nil {
			fmt.Printf("** cleanupCckmAzureVaults: failed to remove vault '%s' (%s): %s\n", azureName, vaultID, err.Error())
		} else {
			fmt.Printf("cleanupCckmAzureVaults: removed vault '%s'\n", azureName)
		}
	}
}

// TestCckmAzureVaultResource exercises the ciphertrust_azure_vault resource.
//
// Sub-tests that do not require live Azure infrastructure (invalid_connection,
// invalid_backup_limit) run before the environment-variable skip check so they
// are never accidentally skipped.
//
// Sub-tests that require a real vault (lifecycle, create_with_vault_details) run
// only when the four core Azure environment variables are set.
func TestCckmAzureVaultResource(t *testing.T) {
	// --- Tests that do not need live Azure infrastructure ---

	t.Run("invalid_connection", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					// A non-existent connection UUID must be rejected at create time.
					Config: `
						resource "ciphertrust_azure_vault" "test" {
							name            = "any-vault"
							connection_id   = "00000000-0000-0000-0000-000000000000"
							subscription_id = "00000000-0000-0000-0000-000000000000"
						}`,
					ExpectError: regexp.MustCompile(`failed to read Azure connection`),
				},
			},
		})
	})

	t.Run("invalid_backup_limit", func(t *testing.T) {
		// The schema validator must reject cloud_key_backup_limit = 0 without
		// contacting any API.
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
						resource "ciphertrust_azure_vault" "test" {
							name                   = "any-vault"
							connection_id          = "00000000-0000-0000-0000-000000000000"
							subscription_id        = "00000000-0000-0000-0000-000000000000"
							cloud_key_backup_limit = 0
						}`,
					ExpectError: regexp.MustCompile(`value must be at least`),
				},
			},
		})
	})

	// --- Tests that require live Azure infrastructure ---

	initConfig, ok := initCckmAzureTestWithoutVault()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureVaultResource live tests")
	}

	// subConfig produces the subscription + vault data sources shared by each step.
	// It can be prepended to any step config.
	subConfig := initConfig + `
		data "ciphertrust_azure_subscription_details" "subs" {
			connection_id = ciphertrust_azure_connection.azure_connection.id
		}`

	// vaultName is the standard vault name read from the environment at test setup time.
	vaultName := os.Getenv("CCKM_TF_AZURE_STANDARD_VAULT")

	t.Run("lifecycle", func(t *testing.T) {
		// Generate a unique name for the second Azure connection used in the update step.
		uid2 := "tf-" + uuid.New().String()[:8]

		// connBlock2 is the HCL for a second Azure connection with the same credentials.
		clientID := os.Getenv("CCKM_TF_AZURE_CLIENT_ID")
		tenantID := os.Getenv("CCKM_TF_AZURE_TENANT_ID")
		clientSecret := os.Getenv("CCKM_TF_AZURE_CLIENT_SECRET")
		connBlock2 := fmt.Sprintf(`
			resource "ciphertrust_azure_connection" "azure_connection2" {
				name          = %q
				client_id     = %q
				tenant_id     = %q
				client_secret = %q
				cloud_name    = "AzureCloud"
				products      = ["cckm"]
			}`, uid2, clientID, tenantID, clientSecret)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				// Step 1: Create vault by name only (no vault_details).
				{
					Config: subConfig + `
						resource "ciphertrust_azure_vault" "test" {
							name            = local.azure_standard_vault
							connection_id   = ciphertrust_azure_connection.azure_connection.id
							subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
						}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "id"),
						resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "name", vaultName),
						resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "cloud_name", "AzureCloud"),
						resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "vault_type"),
						resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "vault_properties.tenant_id"),
						resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "cckm_vault_name"),
					),
				},
				// Step 2: Import by CM resource ID and verify all attributes round-trip.
				{
					ResourceName:            "ciphertrust_azure_vault.test",
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: []string{"vault_details"},
				},
				// Step 3: Set cloud_key_backup_limit.
				{
					Config: subConfig + `
						resource "ciphertrust_azure_vault" "test" {
							name                   = local.azure_standard_vault
							connection_id          = ciphertrust_azure_connection.azure_connection.id
							subscription_id        = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
							cloud_key_backup_limit = 10
						}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "cloud_key_backup_limit", "10"),
					),
				},
				// Step 4: Switch to a second connection; verify connection_name changes.
				{
					Config: subConfig + connBlock2 + `
						resource "ciphertrust_azure_vault" "test" {
							name                   = local.azure_standard_vault
							connection_id          = ciphertrust_azure_connection.azure_connection2.id
							subscription_id        = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
							cloud_key_backup_limit = 10
						}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "connection_name", uid2),
					),
				},
				// Step 5: Attempt to change name - must be rejected by the ImmutableString planmodifier.
				{
					Config: subConfig + connBlock2 + `
						resource "ciphertrust_azure_vault" "test" {
							name                   = "a-different-vault-name"
							connection_id          = ciphertrust_azure_connection.azure_connection2.id
							subscription_id        = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
							cloud_key_backup_limit = 10
						}`,
					ExpectError: regexp.MustCompile(`cannot be changed after creation`),
				},
				// Step 6: Attempt to change subscription_id - must be rejected by the ImmutableString planmodifier.
				{
					Config: subConfig + connBlock2 + `
						resource "ciphertrust_azure_vault" "test" {
							name                   = local.azure_standard_vault
							connection_id          = ciphertrust_azure_connection.azure_connection2.id
							subscription_id        = "00000000-0000-0000-0000-000000000000"
							cloud_key_backup_limit = 10
						}`,
					ExpectError: regexp.MustCompile(`cannot be changed after creation`),
				},
			},
		})
	})

	t.Run("create_with_vault_details", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				// Step 1: Create vault using vault_details from the data source.
				// The data source map is keyed by vault name so vault_details contains the
				// full Azure vault properties without a separate Azure lookup during create.
				// Also exercises ciphertrust_azure_subscription_list with no filter, a single
				// filter, and multiple filters to confirm filter handling works correctly.
				{
					Config: subConfig + `
					data "ciphertrust_azure_vault_details" "vaults" {
							connection_id   = ciphertrust_azure_connection.azure_connection.id
							subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
						}
						resource "ciphertrust_azure_vault" "test" {
							name            = local.azure_standard_vault
							connection_id   = ciphertrust_azure_connection.azure_connection.id
							subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
							vault_details   = data.ciphertrust_azure_vault_details.vaults.vaults[local.azure_standard_vault]
						}
						# No filter - all CCKM-stored subscriptions.
						data "ciphertrust_azure_subscription_list" "all" {
							depends_on = [ciphertrust_azure_vault.test]
						}
						# Single filter - match by Azure subscription ID.
						data "ciphertrust_azure_subscription_list" "by_sub_id" {
							filters = {
								subscriptionId = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
							}
							depends_on = [ciphertrust_azure_vault.test]
						}
						# Filter by display name.
						data "ciphertrust_azure_subscription_list" "by_display_name" {
							filters = {
								displayName = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].display_name
							}
							depends_on = [ciphertrust_azure_vault.test]
						}
						# Filter by limit only (returns up to 3 results).
						data "ciphertrust_azure_subscription_list" "by_limit" {
							filters = {
								limit = "3"
							}
							depends_on = [ciphertrust_azure_vault.test]
						}`,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "id"),
						resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "vault_properties.tenant_id"),
						resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "name", vaultName),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_subscription_list.all", "subscriptions.0.subscription_id"),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_subscription_list.by_sub_id", "subscriptions.0.subscription_id"),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_subscription_list.by_display_name", "subscriptions.0.subscription_id"),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_subscription_list.by_limit", "subscriptions.0.subscription_id"),
					),
				},
				// Step 2: Attempt to change vault_details.name to a different value.
				// ModifyPlan must reject this because it would imply a different vault.
				{
					Config: subConfig + `
						resource "ciphertrust_azure_vault" "test" {
							name            = local.azure_standard_vault
							connection_id   = ciphertrust_azure_connection.azure_connection.id
							subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
							vault_details = {
								name = "a-different-vault"
							}
						}`,
					ExpectError: regexp.MustCompile(`vault_details cannot be modified`),
				},
			},
		})
	})
}
