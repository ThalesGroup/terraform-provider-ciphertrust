package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmAzureVaultListDataSource exercises the ciphertrust_azure_vault_list data source.
//
// The invalid_filter_key sub-test runs without live Azure infrastructure.
// The lifecycle sub-test requires the four core Azure environment variables and
// adds a vault first so there is always at least one result to query.
func TestCckmAzureDataSourceVaultList(t *testing.T) {

	// --- Tests that do not need live Azure infrastructure ---

	t.Run("invalid_filter_key", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
						data "ciphertrust_azure_vault_list" "test" {
							filters = { ekm_configured = "true" }
						}`,
					ExpectError: regexp.MustCompile(`not a supported filter key`),
				},
			},
		})
	})

	// --- Tests that require live Azure infrastructure ---

	initConfig, ok := initCckmAzureTestWithoutVault()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureVaultListDataSource live tests")
	}

	// subConfig provides the subscription data source shared by each step.
	subConfig := initConfig + `
		data "ciphertrust_azure_subscription_details" "subs" {
			connection_id = ciphertrust_azure_connection.azure_connection.id
		}`

	// vaultConfig creates the vault resource that all data source steps depend on.
	vaultConfig := subConfig + `
		resource "ciphertrust_azure_vault" "test" {
			name            = local.azure_standard_vault
			connection_id   = ciphertrust_azure_connection.azure_connection.id
			subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
		}`

	t.Run("valid_filters", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				// Single step: create the vault then exercise all filter variants simultaneously.
				{
					Config: vaultConfig + `

						# No filter - return all vaults (at least the one we just created).
						data "ciphertrust_azure_vault_list" "all" {
							depends_on = [ciphertrust_azure_vault.test]
						}

						# limit = 1 - should return exactly one vault entry.
						data "ciphertrust_azure_vault_list" "by_limit" {
							filters    = { limit = "1" }
							depends_on = [ciphertrust_azure_vault.test]
						}

						# skip = 1 - skip the first result; matched is still the total count.
						data "ciphertrust_azure_vault_list" "by_skip" {
							filters    = { skip = "1" }
							depends_on = [ciphertrust_azure_vault.test]
						}

						# subscription_id filter - must match the vault we just added.
						data "ciphertrust_azure_vault_list" "by_sub" {
							filters = {
								subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
							}
							depends_on = [ciphertrust_azure_vault.test]
						}

						# name filter - use cckm_vault_name from the resource (azure_name::subscription_id format).
						data "ciphertrust_azure_vault_list" "by_name" {
							filters = {
								name = ciphertrust_azure_vault.test.cckm_vault_name
							}
						}

						# type = "vault" - Key Vaults only; our added vault qualifies.
						data "ciphertrust_azure_vault_list" "by_type_vault" {
							filters    = { type = "vault" }
							depends_on = [ciphertrust_azure_vault.test]
						}

						# type = "managedHsm" - no managed HSMs added, so matched = 0.
						data "ciphertrust_azure_vault_list" "by_type_hsm" {
							filters    = { type = "managedHsm" }
							depends_on = [ciphertrust_azure_vault.test]
						}

						# sort = "-createdAt" - most-recently added vault first; verify no error.
						data "ciphertrust_azure_vault_list" "by_sort" {
							filters    = { sort = "-createdAt" }
							depends_on = [ciphertrust_azure_vault.test]
						}`,

					Check: resource.ComposeTestCheckFunc(
						// No-filter list: at least one vault is present.
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.all", "matched"),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.all", "vaults.0.id"),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.all", "vaults.0.name"),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.all", "vaults.0.vault_properties.tenant_id"),

						// limit = 1: exactly one entry returned.
						resource.TestCheckResourceAttr("data.ciphertrust_azure_vault_list.by_limit", "vaults.#", "1"),

						// skip = 1: matched is still the full total.
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.by_skip", "matched"),

						// subscription_id filter: at least one vault found.
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.by_sub", "vaults.0.id"),

						// name filter using cckm_vault_name: exactly the added vault is returned.
						resource.TestCheckResourceAttr("data.ciphertrust_azure_vault_list.by_name", "matched", "1"),
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.by_name", "vaults.0.id"),

						// type = "vault": at least one vault found.
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.by_type_vault", "vaults.0.id"),

						// type = "managedHsm": no vaults added, matched must be 0.
						resource.TestCheckResourceAttr("data.ciphertrust_azure_vault_list.by_type_hsm", "matched", "0"),

						// sort: no error; at least one vault present.
						resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vault_list.by_sort", "vaults.0.id"),
					),
				},
			},
		})
	})
}
