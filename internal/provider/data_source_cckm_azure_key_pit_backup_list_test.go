package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmAzureDataSourceKeyPitBackupList exercises the ciphertrust_azure_key_pit_backup_list data source.
//
// Only validation is covered here. Listing real backups is covered by TestCckmAzureKeyPremiumVault,
// which creates them with the ciphertrust_azure_key_pit_backup resource.
// These sub-tests run without live Azure infrastructure.
func TestCckmAzureDataSourceKeyPitBackupList(t *testing.T) {

	t.Run("invalid_filter_key", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
						data "ciphertrust_azure_key_pit_backup_list" "test" {
							key_id  = "00000000-0000-0000-0000-000000000000"
							filters = { key_name = "abc" }
						}`,
					ExpectError: regexp.MustCompile(`not a supported filter key`),
				},
			},
		})
	})

	t.Run("missing_key_id", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: `
						data "ciphertrust_azure_key_pit_backup_list" "test" {
						}`,
					ExpectError: regexp.MustCompile(`key_id`),
				},
			},
		})
	})
}
