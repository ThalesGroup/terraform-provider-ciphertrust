package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestCckmAzureKeyPremiumVault covers every premium vault scenario with two keys in total, so the vault is
// not filled with keys. Each case is a separate test run because the provider settings apply when the key is
// destroyed. The subtests run in order and share the captured key and backup IDs.
//
// Key 1 (uploaded HSM key, exportable with a release policy when CCKM_TF_AZURE_RELEASE_POLICY is set):
//
//  1. upload_hsm_key: upload with hsm, exportable and a release policy, then import. Destroy purges the key
//     and retains its backups.
//  2. restore_soft_delete_only: restore the key from its backups. Destroy only soft-deletes it.
//  3. recover_purge_delete_backups: recover the soft-deleted key with a native key of the same name. Destroy
//     purges it and deletes its backups.
//  4. restore_after_backups_deleted: restore fails because the backups are gone.
//
// Key 2 (native RSA-HSM key, ciphertrust_azure_key_pit_backup resource):
//
//  5. create_pit_backup: create the key and a PIT backup, and check the computed attributes and the
//     ciphertrust_azure_key_pit_backup_list data source. Destroy purges the key and retains its backups.
//  6. restore_from_pit_backup: restore the key from the PIT backup. This also checks whether CipherTrust
//     Manager allows a restore while a record with the same key name still exists.
//
// It needs CCKM_TF_AZURE_PREMIUM_VAULT. CCKM_TF_AZURE_RELEASE_POLICY (a JSON object string) is optional. When
// it is not set, key 1 is created without exportable and release_policy, and those attributes are not checked.
func TestCckmAzureKeyPremiumVault(t *testing.T) {
	initConfig, ok := initCckmAzureTestPremiumVault()
	if !ok {
		t.Skip("Azure environment variables or CCKM_TF_AZURE_PREMIUM_VAULT not set - skipping TestCckmAzureKeyPremiumVault")
	}
	releasePolicy := os.Getenv("CCKM_TF_AZURE_RELEASE_POLICY")

	// Azure only allows an exportable key with a release policy, so both are set together or not at all.
	policyAttrs := ""
	if releasePolicy != "" {
		policyAttrs = fmt.Sprintf(`
			exportable     = true
			release_policy = %q`, releasePolicy)
	}
	policyCheck := func(name string) resource.TestCheckFunc {
		if releasePolicy == "" {
			return func(*terraform.State) error { return nil }
		}
		return resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(name, "exportable", "true"),
			resource.TestCheckResourceAttr(name, "release_policy", releasePolicy),
		)
	}
	// A restored key has no configured release_policy, so state holds the compact JSON returned by the server.
	restoredPolicyCheck := func(name string) resource.TestCheckFunc {
		if releasePolicy == "" {
			return func(*terraform.State) error { return nil }
		}
		return resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckResourceAttr(name, "exportable", "true"),
			testCheckAzureKeyJSONEquivalent(name, "release_policy", releasePolicy),
		)
	}

	premiumVaultResource := "ciphertrust_azure_vault.premium_vault"
	uploadResource := "ciphertrust_azure_key.upload_key"
	restoredResource := "ciphertrust_azure_key.restored_key"
	nativeResource := "ciphertrust_azure_key.native_key"

	// Key 1.
	cmKeyName := "tf-cm-" + uuid.NewString()[:8]
	uploadKeyName := "tf-" + uuid.NewString()[:8]
	var uploadKeyID, uploadBackupID string

	// kty, curve and key_size are not asserted for the uploaded key because Azure reports them according
	// to the vault.
	uploadConfig := fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_rsa_key" {
			name      = %q
			algorithm = "RSA"
			key_size  = 2048
		}
		resource "ciphertrust_azure_key" "upload_key" {
			vault_id = ciphertrust_azure_vault.premium_vault.id
			name     = %q
			upload_key = {
				source_key_tier = "local"
				source_key_id   = ciphertrust_cm_key.cm_rsa_key.id
				hsm             = true
			}
			%s
		}`, cmKeyName, uploadKeyName, policyAttrs)

	t.Run("upload_hsm_key", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Upload exportable HSM key, destroy with purge and retain") },
					Config:    azureProviderSettingsConfig(initConfig+uploadConfig, true, false, true),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(uploadResource, "id"),
						resource.TestCheckResourceAttrPair(uploadResource, "vault_id", premiumVaultResource, "id"),
						resource.TestCheckResourceAttr(uploadResource, "name", uploadKeyName),
						resource.TestCheckResourceAttr(uploadResource, "upload_key.source_key_tier", "local"),
						resource.TestCheckResourceAttrPair(uploadResource, "upload_key.source_key_id", "ciphertrust_cm_key.cm_rsa_key", "id"),
						resource.TestCheckResourceAttr(uploadResource, "upload_key.hsm", "true"),
						resource.TestCheckResourceAttr(uploadResource, "upload_key.local_key_name", cmKeyName),
						resource.TestCheckResourceAttr(uploadResource, "azure_params.key.kty", "RSA-HSM"),
						policyCheck(uploadResource),
						resource.TestCheckResourceAttrSet(uploadResource, "azure_params.key.kid"),
						func(s *terraform.State) error {
							rs, found := s.RootModule().Resources[uploadResource]
							if !found {
								return fmt.Errorf("resource %s not found in state", uploadResource)
							}
							uploadKeyID = rs.Primary.ID
							uploadBackupID = rs.Primary.Attributes["backup"]
							return nil
						},
					),
				},
				{
					PreConfig:         func() { logTestStep(t.Name(), "Import") },
					Config:            azureProviderSettingsConfig(initConfig+uploadConfig, true, false, true),
					ResourceName:      uploadResource,
					ImportState:       true,
					ImportStateVerify: true,
					// release_policy is ignored because the imported value is the compact JSON returned by
					// the server, while state keeps the configured formatting. The step above checks it.
					ImportStateVerifyIgnore: append(append([]string{}, importStateVerifyIgnoreAzureKey...), "release_policy"),
				},
			},
		})
	})

	t.Run("restore_soft_delete_only", func(t *testing.T) {
		if uploadKeyID == "" {
			t.Skip("key ID was not captured - skipping restore_soft_delete_only")
		}
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "restored_key" {
				vault_id = ciphertrust_azure_vault.premium_vault.id
				restore_key = {
					key_id = %q
				}
			}`, uploadKeyID)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Restore key, destroy with soft-delete only") },
					Config:    azureProviderSettingsConfig(initConfig+restoreConfig, false, false, true),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrPair(restoredResource, "vault_id", premiumVaultResource, "id"),
						resource.TestCheckResourceAttr(restoredResource, "restore_key.key_id", uploadKeyID),
						resource.TestCheckResourceAttr(restoredResource, "id", uploadKeyID),
						resource.TestCheckResourceAttr(restoredResource, "name", uploadKeyName),
						restoredPolicyCheck(restoredResource),
					),
				},
			},
		})
	})

	t.Run("recover_purge_delete_backups", func(t *testing.T) {
		if uploadKeyID == "" {
			t.Skip("key ID was not captured - skipping recover_purge_delete_backups")
		}
		// A native key is used because only ciphertrust_azure_key recovers a soft-deleted key of the same name.
		recoverConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "native_key" {
				vault_id = ciphertrust_azure_vault.premium_vault.id
				name     = %q
				%s
				azure_params = {
					key = {
						kty = "RSA-HSM"
					}
					key_size = 2048
				}
			}`, uploadKeyName, policyAttrs)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Recover soft-deleted key, destroy with purge and backup deletion") },
					Config:    azureProviderSettingsConfig(initConfig+recoverConfig, true, true, false),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrPair(nativeResource, "vault_id", premiumVaultResource, "id"),
						resource.TestCheckResourceAttr(nativeResource, "name", uploadKeyName),
						policyCheck(nativeResource),
					),
				},
			},
		})
	})

	t.Run("restore_after_backups_deleted", func(t *testing.T) {
		if uploadKeyID == "" {
			t.Skip("key ID was not captured - skipping restore_after_backups_deleted")
		}
		backupLine := ""
		if uploadBackupID != "" {
			backupLine = fmt.Sprintf("backup_id = %q", uploadBackupID)
		}
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "restored_key" {
				vault_id = ciphertrust_azure_vault.premium_vault.id
				restore_key = {
					key_id = %q
					%s
				}
			}`, uploadKeyID, backupLine)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Restore key after its backups were deleted") },
					Config:    azureProviderSettingsConfig(initConfig+restoreConfig, true, false, true),
					// The error text is not asserted beyond a loose match.
					ExpectError: regexp.MustCompile(`(?is)error|not found|fail`),
				},
			},
		})
	})

	// Key 2.
	pitKeyName := "tf-" + uuid.NewString()[:8]
	backupName := "tf-bk-" + uuid.NewString()[:8]
	backupResource := "ciphertrust_azure_key_pit_backup.backup"
	listDataSource := "data.ciphertrust_azure_key_pit_backup_list.backups"
	var pitKeyID, pitBackupID string

	backupConfig := fmt.Sprintf(`
		resource "ciphertrust_azure_key" "native_key" {
			vault_id = ciphertrust_azure_vault.premium_vault.id
			name     = %q
			azure_params = {
				key = {
					kty = "RSA-HSM"
				}
				key_size = 2048
			}
		}
		resource "ciphertrust_azure_key_pit_backup" "backup" {
			key_id      = ciphertrust_azure_key.native_key.id
			trigger     = "one"
			name        = %q
			description = "terraform acceptance test"
		}
		data "ciphertrust_azure_key_pit_backup_list" "backups" {
			key_id     = ciphertrust_azure_key.native_key.id
			depends_on = [ciphertrust_azure_key_pit_backup.backup]
		}`, pitKeyName, backupName)

	t.Run("create_pit_backup", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Create key and PIT backup, destroy with purge and retain") },
					Config:    azureProviderSettingsConfig(initConfig+backupConfig, true, false, true),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrPair(backupResource, "key_id", nativeResource, "id"),
						resource.TestCheckResourceAttr(backupResource, "trigger", "one"),
						resource.TestCheckResourceAttr(backupResource, "name", backupName),
						resource.TestCheckResourceAttr(backupResource, "description", "terraform acceptance test"),
						resource.TestCheckResourceAttr(backupResource, "key_name", pitKeyName),
						resource.TestCheckResourceAttr(backupResource, "gone", "false"),
						resource.TestCheckResourceAttrSet(backupResource, "id"),
						resource.TestCheckResourceAttrSet(backupResource, "backup"),
						resource.TestCheckResourceAttrSet(backupResource, "created_at"),
						resource.TestCheckResourceAttrSet(backupResource, "vault_name"),
						resource.TestCheckResourceAttrSet(backupResource, "subscription_id"),
						resource.TestCheckResourceAttrSet(backupResource, "region"),
						resource.TestCheckResourceAttrPair(listDataSource, "backups.0.id", backupResource, "id"),
						func(s *terraform.State) error {
							key, found := s.RootModule().Resources[nativeResource]
							if !found {
								return fmt.Errorf("resource %s not found in state", nativeResource)
							}
							backup, found := s.RootModule().Resources[backupResource]
							if !found {
								return fmt.Errorf("resource %s not found in state", backupResource)
							}
							pitKeyID = key.Primary.ID
							pitBackupID = backup.Primary.ID
							return nil
						},
					),
				},
			},
		})
	})

	t.Run("restore_from_pit_backup", func(t *testing.T) {
		if pitKeyID == "" || pitBackupID == "" {
			t.Skip("key or backup ID was not captured - skipping restore_from_pit_backup")
		}
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "restored_key" {
				vault_id = ciphertrust_azure_vault.premium_vault.id
				restore_key = {
					key_id    = %q
					backup_id = %q
				}
			}`, pitKeyID, pitBackupID)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Restore key from the PIT backup, destroy with purge") },
					Config:    azureProviderSettingsConfig(initConfig+restoreConfig, true, false, true),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrPair(restoredResource, "vault_id", premiumVaultResource, "id"),
						resource.TestCheckResourceAttr(restoredResource, "name", pitKeyName),
						resource.TestCheckResourceAttr(restoredResource, "restore_key.key_id", pitKeyID),
						resource.TestCheckResourceAttr(restoredResource, "restore_key.backup_id", pitBackupID),
					),
				},
			},
		})
	})
}
