package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// importStateVerifyIgnoreAzureKey lists attributes that cannot round-trip through
// terraform import for an Azure key.
//   - restore_key, upload_key: input-only, not returned by the API.
//   - enable_auto_rotation, enable_auto_backup: rebuilt from labels or backup_config
//     on import, so they may not match the configured scheduler details.
//   - activation_date, expiration_date: the API never returns nbf or exp for a key.
var importStateVerifyIgnoreAzureKey = []string{
	"enable_auto_rotation",
	"enable_auto_backup",
	"restore_key",
	"upload_key",
	"azure_params.attributes.activation_date",
	"azure_params.attributes.expiration_date",
}

// testCheckAzureKeyJSONEquivalent checks that a JSON string attribute is semantically equal to
// expected, ignoring formatting.
func testCheckAzureKeyJSONEquivalent(name, attr, expected string) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith(name, attr, func(value string) error {
		var want, got interface{}
		if err := json.Unmarshal([]byte(expected), &want); err != nil {
			return fmt.Errorf("expected value for %s is not valid JSON: %w", attr, err)
		}
		if err := json.Unmarshal([]byte(value), &got); err != nil {
			return fmt.Errorf("%s is not valid JSON: %w", attr, err)
		}
		if !reflect.DeepEqual(want, got) {
			return fmt.Errorf("%s is not JSON equivalent: expected %s, got %s", attr, expected, value)
		}
		return nil
	})
}

// initCckmAzureTest returns the shared Azure test configuration plus the subscription details
// data source and the nonpurgeable vault resource (ciphertrust_azure_vault.nonpurgeable_vault).
// It returns false when the Azure environment variables are not set.
func initCckmAzureTest(timeout ...int) (string, bool) {
	initConfig, ok := initCckmAzureTestWithoutVault(timeout...)
	if !ok {
		return "", false
	}
	vaultConfig := `
		data "ciphertrust_azure_subscription_details" "subs" {
			connection_id = ciphertrust_azure_connection.azure_connection.id
		}
		resource "ciphertrust_azure_vault" "nonpurgeable_vault" {
			name            = local.azure_nonpurgeable_vault
			connection_id   = ciphertrust_azure_connection.azure_connection.id
			subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
		}`
	return initConfig + vaultConfig, true
}

// initCckmAzureTestPurgeableVault returns the configuration from initCckmAzureTest plus the purgeable
// vault resource (ciphertrust_azure_vault.purgeable_vault). It returns false when the Azure
// environment variables are not set or CCKM_TF_AZURE_PURGEABLE_VAULT is empty.
func initCckmAzureTestPurgeableVault(timeout ...int) (string, bool) {
	if os.Getenv("CCKM_TF_AZURE_PURGEABLE_VAULT") == "" {
		return "", false
	}
	initConfig, ok := initCckmAzureTest(timeout...)
	if !ok {
		return "", false
	}
	purgeableVaultConfig := `
		resource "ciphertrust_azure_vault" "purgeable_vault" {
			name            = local.azure_purgeable_vault
			connection_id   = ciphertrust_azure_connection.azure_connection.id
			subscription_id = data.ciphertrust_azure_subscription_details.subs.subscriptions[0].subscription_id
		}`
	return initConfig + purgeableVaultConfig, true
}

// TestCckmAzureKeyNative exercises create, update, import and tag/scheduler removal of a native
// ciphertrust_azure_key in the nonpurgeable vault.
func TestCckmAzureKeyNative(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureKeyNative")
	}

	activationTime := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	activationDate := activationTime.Format(time.RFC3339)
	expirationDate := activationTime.AddDate(1, 0, 0).Format(time.RFC3339)
	newActivationDate := activationTime.AddDate(0, 1, 0).Format(time.RFC3339)
	newExpirationDate := activationTime.AddDate(1, 1, 0).Format(time.RFC3339)

	// createConfig args: key name, activation date, expiration date, tags.
	createConfig := `
		resource "ciphertrust_azure_key" "native_key" {
			vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
			name     = "%s"
			azure_params = {
				key = {
					kty     = "RSA"
					key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
				}
				key_size = 2048
				attributes = {
					enabled         = true
					activation_date = "%s"
					expiration_date = "%s"
				}
				# Placeholder for tags.
				%s
			}
		}`

	// updateConfig args: backup scheduler name, rotation scheduler name, key name, activation date,
	// expiration date, tags,
	// rotation key_source, rotation key_type, rotation ec_name line, rotation key_size line.
	updateConfig := `
		resource "ciphertrust_scheduler" "backup_scheduler" {
			name      = "%s"
			operation = "cckm_key_backup"
			run_at    = "0 9 * * fri"
			run_on    = "any"
			cckm_key_backup_params = {
				cloud_name = "AzureCloud"
			}
		}
		resource "ciphertrust_scheduler" "rotation_scheduler" {
			name      = "%s"
			operation = "cckm_key_rotation"
			run_at    = "0 9 * * fri"
			run_on    = "any"
			cckm_key_rotation_params = {
				cloud_name = "AzureCloud"
				expiration = "365d"
				expire_in  = "10d"
			}
		}
		resource "ciphertrust_azure_key" "native_key" {
			vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
			name     = "%s"
			azure_params = {
				key = {
					kty     = "RSA"
					key_ops = ["encrypt", "decrypt"]
				}
				key_size = 2048
				attributes = {
					enabled         = false
					activation_date = "%s"
					expiration_date = "%s"
				}
				# Placeholder for tags.
				%s
			}
			enable_auto_backup = {
				job_config_id = ciphertrust_scheduler.backup_scheduler.id
			}
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.rotation_scheduler.id
				key_source    = "%s"
				key_type      = "%s"
				# Placeholder for ec_name.
				%s
				# Placeholder for key_size.
				%s
			}
		}`

	keyName := "tf-" + uuid.NewString()[:8]
	backupSchedulerName := "tf-" + uuid.NewString()[:8]
	rotationSchedulerName := "tf-" + uuid.NewString()[:8]
	keyResource := "ciphertrust_azure_key.native_key"
	vaultResource := "ciphertrust_azure_vault.nonpurgeable_vault"
	backupSchedulerResource := "ciphertrust_scheduler.backup_scheduler"
	rotationSchedulerResource := "ciphertrust_scheduler.rotation_scheduler"

	createTags := `tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}`
	updateTags := `tags = {
					TagKey2 = "TagValue2Updated"
					TagKey3 = "TagValue3"
				}`
	removeTags := `tags = {}`

	createConfigStr := initConfig + fmt.Sprintf(createConfig, keyName, activationDate, expirationDate, createTags)
	updateConfigStr1 := initConfig + applyCDSPAAS(fmt.Sprintf(updateConfig,
		backupSchedulerName, rotationSchedulerName, keyName, newActivationDate, newExpirationDate, updateTags,
		"native", "EC", `ec_name = "P-256"`, ""))
	updateConfigStr2 := initConfig + applyCDSPAAS(fmt.Sprintf(updateConfig,
		backupSchedulerName, rotationSchedulerName, keyName, newActivationDate, newExpirationDate, updateTags,
		"ciphertrust", "RSA", "", "key_size = 3072"))
	resetConfigStr := initConfig + fmt.Sprintf(createConfig, keyName, activationDate, expirationDate, removeTags)

	// nativeKeyID is the CipherTrust Manager ID of the key created by the main test. It is captured
	// in the last step and used by the restore sub-test.
	var nativeKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create an enabled native RSA key with activation and expiry dates.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    createConfigStr,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrPair(keyResource, "vault_id", vaultResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
					resource.TestCheckResourceAttrSet(keyResource, "vault_name"),
					resource.TestCheckResourceAttrSet(keyResource, "account"),
					resource.TestCheckResourceAttrSet(keyResource, "cloud_name"),
					resource.TestCheckResourceAttrSet(keyResource, "created_at"),
					resource.TestCheckResourceAttrSet(keyResource, "updated_at"),
					resource.TestCheckResourceAttrSet(keyResource, "region"),
					resource.TestCheckResourceAttrSet(keyResource, "status"),
					resource.TestCheckResourceAttrSet(keyResource, "tenant"),
					resource.TestCheckResourceAttrSet(keyResource, "version"),
					resource.TestCheckResourceAttr(keyResource, "version_count", "1"),
					resource.TestCheckResourceAttr(keyResource, "deleted", "false"),
					resource.TestCheckResourceAttr(keyResource, "exportable", "false"),
					resource.TestCheckResourceAttr(keyResource, "key_material_origin", "native"),
					resource.TestCheckResourceAttr(keyResource, "key_soft_deleted_in_azure", "false"),
					resource.TestCheckResourceAttrSet(keyResource, "soft_delete_enabled"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.kty", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "6"),
					resource.TestCheckResourceAttrSet(keyResource, "azure_params.key.kid"),
					resource.TestCheckResourceAttrSet(keyResource, "azure_params.key.n"),
					resource.TestCheckResourceAttrSet(keyResource, "azure_params.key.e"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key_size", "2048"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.activation_date", activationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", expirationDate),
					resource.TestCheckResourceAttrSet(keyResource, "azure_params.attributes.recovery_level"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey2", "TagValue2"),
					resource.TestCheckNoResourceAttr(keyResource, "enable_auto_backup"),
					resource.TestCheckNoResourceAttr(keyResource, "enable_auto_rotation"),
				),
			},
			// Step 2: attach a backup scheduler and a native EC rotation scheduler, disable the key,
			// update key_ops, replace the tags and change the dates.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 2") },
				Config:    updateConfigStr1,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.kty", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key_size", "2048"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.activation_date", newActivationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", newExpirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
					resource.TestCheckNoResourceAttr(keyResource, "azure_params.tags.TagKey1"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey2", "TagValue2Updated"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey3", "TagValue3"),
					resource.TestCheckResourceAttrPair(keyResource, "enable_auto_backup.job_config_id", backupSchedulerResource, "id"),
					resource.TestCheckResourceAttrPair(keyResource, "backup_config.backup_job_config_id", backupSchedulerResource, "id"),
					resource.TestCheckResourceAttrPair(keyResource, "enable_auto_rotation.job_config_id", rotationSchedulerResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_auto_rotation.key_source", "native"),
					resource.TestCheckResourceAttr(keyResource, "enable_auto_rotation.key_type", "EC"),
					resource.TestCheckResourceAttr(keyResource, "enable_auto_rotation.ec_name", "P-256"),
					resource.TestCheckNoResourceAttr(keyResource, "enable_auto_rotation.key_size"),
				),
			},
			// Step 3: change the rotation to a ciphertrust RSA key source with a key size.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 3") },
				Config:    updateConfigStr2,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
					resource.TestCheckResourceAttrPair(keyResource, "enable_auto_backup.job_config_id", backupSchedulerResource, "id"),
					resource.TestCheckResourceAttrPair(keyResource, "backup_config.backup_job_config_id", backupSchedulerResource, "id"),
					resource.TestCheckResourceAttrPair(keyResource, "enable_auto_rotation.job_config_id", rotationSchedulerResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_auto_rotation.key_source", "ciphertrust"),
					resource.TestCheckResourceAttr(keyResource, "enable_auto_rotation.key_type", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "enable_auto_rotation.key_size", "3072"),
					resource.TestCheckNoResourceAttr(keyResource, "enable_auto_rotation.ec_name"),
				),
			},
			// Step 4: import the key while both schedulers are attached.
			{
				PreConfig:               func() { logTestStep(t.Name(), "Step 4 import") },
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAzureKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			// Step 5: apply createConfig with tags = {}. Tags and schedulers are removed, the key
			// is enabled again and key_ops and the dates return to their createConfig values.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 5") },
				Config:    resetConfigStr,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "6"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.activation_date", activationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", expirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "0"),
					resource.TestCheckNoResourceAttr(keyResource, "enable_auto_backup"),
					resource.TestCheckNoResourceAttr(keyResource, "enable_auto_rotation"),
					resource.TestCheckNoResourceAttr(keyResource, "backup_config.backup_job_config_id"),
					func(s *terraform.State) error {
						rs, found := s.RootModule().Resources[keyResource]
						if !found {
							return fmt.Errorf("resource %s not found in state", keyResource)
						}
						nativeKeyID = rs.Primary.ID
						return nil
					},
				),
			},
		},
	})

	// CCKM keeps a backup of every key, so the key above can be restored after it has been deleted
	// from the nonpurgeable vault. A key can only be restored to a different vault, so the purgeable
	// vault is used. Inside the sub-test t is the sub-test's own value, so the state of this test is
	// captured here.
	nativeFailed := t.Failed()
	t.Run("restore_soft_deleted_to_another_vault", func(t *testing.T) {
		if nativeFailed {
			t.Skip("Previous steps failed")
		}
		purgeableConfig, ok := initCckmAzureTestPurgeableVault()
		if !ok {
			t.Skip("CCKM_TF_AZURE_PURGEABLE_VAULT not set - skipping restore_to_purgeable_vault sub-test")
		}
		restoreConfig := `
			resource "ciphertrust_azure_key" "restored_key" {
				vault_id   = ciphertrust_azure_vault.purgeable_vault.id
				# The nonpurgeable vault holds the soft-deleted key. It must be added back to CCKM before the restore.
				depends_on = [ciphertrust_azure_vault.nonpurgeable_vault]
				restore_key = {
					key_id = "%s"
				}
			}`
		restoredResource := "ciphertrust_azure_key.restored_key"
		purgeableVaultResource := "ciphertrust_azure_vault.purgeable_vault"

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Restore step") },
					Config:    purgeableConfig + fmt.Sprintf(restoreConfig, nativeKeyID),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(restoredResource, "id"),
						resource.TestCheckResourceAttrPair(restoredResource, "vault_id", purgeableVaultResource, "id"),
						resource.TestCheckResourceAttr(restoredResource, "restore_key.key_id", nativeKeyID),
						resource.TestCheckResourceAttr(restoredResource, "name", keyName),
						resource.TestCheckResourceAttr(restoredResource, "azure_params.key.kty", "RSA"),
					),
				},
			},
		})
	})
}

// TestCckmAzureKeyUpload exercises upload of a CipherTrust Manager key (upload_key.source_key_tier = local) into the
// nonpurgeable vault: create, update of tags, key_ops and dates, import and tag removal.
func TestCckmAzureKeyUpload(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureKeyUpload")
	}

	// cmKeyConfig is the CipherTrust Manager RSA key that is uploaded to Azure. The %s is the key name.
	cmKeyConfig := `
		resource "ciphertrust_cm_key" "cm_rsa_key" {
			name      = "%s"
			algorithm = "RSA"
			key_size  = 2048
		}`

	activationTime := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	activationDate := activationTime.Format(time.RFC3339)
	expirationDate := activationTime.AddDate(1, 0, 0).Format(time.RFC3339)
	newActivationDate := activationTime.AddDate(0, 1, 0).Format(time.RFC3339)
	newExpirationDate := activationTime.AddDate(1, 1, 0).Format(time.RFC3339)

	// localCreateConfig args: cm key name, azure key name, activation date, expiration date, tags.
	localCreateConfig := cmKeyConfig + `
		resource "ciphertrust_azure_key" "upload_key" {
			vault_id             = ciphertrust_azure_vault.nonpurgeable_vault.id
			name                 = "%s"
			upload_key = {
				source_key_tier = "local"
				source_key_id   = ciphertrust_cm_key.cm_rsa_key.id
			}
			azure_params = {
				key = {
					key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
				}
				attributes = {
					enabled         = true
					activation_date = "%s"
					expiration_date = "%s"
				}
				# Placeholder for tags.
				%s
			}
		}`

	// localUpdateConfig args: cm key name, azure key name, activation date, expiration date, tags.
	localUpdateConfig := cmKeyConfig + `
		resource "ciphertrust_azure_key" "upload_key" {
			vault_id             = ciphertrust_azure_vault.nonpurgeable_vault.id
			name                 = "%s"
			upload_key = {
				source_key_tier = "local"
				source_key_id   = ciphertrust_cm_key.cm_rsa_key.id
			}
			azure_params = {
				key = {
					key_ops = ["encrypt", "decrypt"]
				}
				attributes = {
					enabled         = false
					activation_date = "%s"
					expiration_date = "%s"
				}
				# Placeholder for tags.
				%s
			}
		}`

	// pfxConfig uploads a pfx using the same key name as localCreateConfig so that a new
	// version is added to the existing key. It takes %s for the azure key name, the pfx file path and the
	// pfx password.
	pfxConfig := `
		resource "ciphertrust_azure_key" "upload_key_pfx" {
			depends_on      = [ciphertrust_azure_key.upload_key]
			vault_id        = ciphertrust_azure_vault.nonpurgeable_vault.id
			name            = "%s"
			upload_key = {
				source_key_tier = "pfx"
				pfx             = "%s"
				pfx_password    = "%s"
			}
			azure_params = {
				key = {
					key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
				}
			}
		}`

	cmKeyName := "tf-cm-" + uuid.NewString()[:8]
	keyName := "tf-" + uuid.NewString()[:8]
	keyResource := "ciphertrust_azure_key.upload_key"
	vaultResource := "ciphertrust_azure_vault.nonpurgeable_vault"

	createTags := `tags = {
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}`
	updateTags := `tags = {
				TagKey2 = "TagValue2Updated"
				TagKey3 = "TagValue3"
			}`
	removeTags := `tags = {}`

	createConfigStr := initConfig + fmt.Sprintf(localCreateConfig, cmKeyName, keyName, activationDate, expirationDate, createTags)
	updateConfigStr := initConfig + fmt.Sprintf(localUpdateConfig, cmKeyName, keyName, newActivationDate, newExpirationDate, updateTags)
	resetConfigStr := initConfig + fmt.Sprintf(localCreateConfig, cmKeyName, keyName, activationDate, expirationDate, removeTags)

	// immutableConfig is the key as created in step 1 with one input changed. Args: cm key name,
	// vault_id expression, azure key name, upload_key.source_key_tier, upload_key.source_key_id expression.
	immutableConfig := cmKeyConfig + `
		resource "ciphertrust_azure_key" "upload_key" {
			vault_id             = %s
			name                 = "%s"
			upload_key = {
				source_key_tier = "%s"
				source_key_id   = %s
			}
		}`
	immutableConfigStr := func(vaultID, name, tier, localKeyID string) string {
		return initConfig + fmt.Sprintf(immutableConfig, cmKeyName, vaultID, name, tier, localKeyID)
	}
	immutableError := regexp.MustCompile(`Attribute\s+is\s+immutable`)
	vaultExpr := vaultResource + ".id"
	localKeyExpr := "ciphertrust_cm_key.cm_rsa_key.id"

	// optionalConfigStr is the key as created in step 1 with optional attributes left out. Args: the
	// azure_params.key block (key_ops), the expiration_date line and the tags. An empty string leaves
	// that part out of the config.
	expirationLine := fmt.Sprintf(`expiration_date = "%s"`, expirationDate)
	optionalConfigStr := func(keyBlock, expiration, tags string) string {
		return initConfig + fmt.Sprintf(cmKeyConfig, cmKeyName) + fmt.Sprintf(`
			resource "ciphertrust_azure_key" "upload_key" {
				vault_id             = ciphertrust_azure_vault.nonpurgeable_vault.id
				name                 = "%s"
				upload_key = {
					source_key_tier = "local"
					source_key_id   = ciphertrust_cm_key.cm_rsa_key.id
				}
				azure_params = {
					%s
					attributes = {
						enabled         = true
						activation_date = "%s"
						%s
					}
					%s
				}
			}`, keyName, keyBlock, activationDate, expiration, tags)
	}

	// Optional step 5: upload a pfx with the same key name to add a new version to the key. The pfx is
	// supplied as base64 text in CCKM_TF_AZURE_PFX with its password in CCKM_TF_AZURE_PFX_PWD. The step is
	// skipped when either is empty.
	pfxResource := "ciphertrust_azure_key.upload_key_pfx"
	var pfxUploadSteps []resource.TestStep
	pfxBase64 := os.Getenv("CCKM_TF_AZURE_PFX")
	pfxPassword := os.Getenv("CCKM_TF_AZURE_PFX_PWD")
	if pfxBase64 != "" && pfxPassword != "" {
		pfxBytes, err := base64.StdEncoding.DecodeString(pfxBase64)
		if err != nil {
			t.Fatalf("unable to decode CCKM_TF_AZURE_PFX as base64: %v", err)
		}
		pfxPath := filepath.Join(t.TempDir(), "azure-upload-test.pfx")
		if err = os.WriteFile(pfxPath, pfxBytes, 0600); err != nil {
			t.Fatalf("unable to write the test pfx: %v", err)
		}
		// The list data sources read the versions of the key. Both depend on the two resources so that
		// they are read after the second version exists. The kid and the version of a key version are
		// not compared with the first version: the list is the source of truth for what the latest
		// version is.
		listConfig := `
			# Every version of the key.
			data "ciphertrust_azure_key_list" "all_versions" {
				filters = {
					key_vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
					key_name     = "%s"
					limit        = "-1"
				}
				depends_on = [ciphertrust_azure_key.upload_key, ciphertrust_azure_key.upload_key_pfx]
			}

			# Only the latest version of the key.
			data "ciphertrust_azure_key_list" "latest" {
				filters = {
					key_vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
					key_name     = "%s"
					version      = "-1"
				}
				depends_on = [ciphertrust_azure_key.upload_key, ciphertrust_azure_key.upload_key_pfx]
			}
			data "ciphertrust_azure_key_list" "rsa_algorithm" {
				filters = {
					key_vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
					key_name     = "%s"
					algorithm    = "rsa"
					limit        = "-1"
				}
				depends_on = [ciphertrust_azure_key.upload_key, ciphertrust_azure_key.upload_key_pfx]
			}`
		allVersions := "data.ciphertrust_azure_key_list.all_versions"
		latest := "data.ciphertrust_azure_key_list.latest"
		rsaAlgorithm := "data.ciphertrust_azure_key_list.rsa_algorithm"
		pfxConfigStr := resetConfigStr + fmt.Sprintf(pfxConfig, keyName, filepath.ToSlash(pfxPath), pfxPassword) +
			fmt.Sprintf(listConfig, keyName, keyName, keyName)
		pfxUploadSteps = append(pfxUploadSteps, resource.TestStep{
			PreConfig: func() { logTestStep(t.Name(), "Step 5") },
			Config:    pfxConfigStr,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(pfxResource, "name", keyName),
				resource.TestCheckResourceAttr(pfxResource, "upload_key.source_key_tier", "pfx"),
				resource.TestCheckResourceAttrPair(pfxResource, "vault_id", vaultResource, "id"),
				resource.TestCheckResourceAttrSet(pfxResource, "id"),
				resource.TestCheckResourceAttrSet(pfxResource, "azure_params.key.kid"),

				// Two versions exist: the local key upload and the pfx upload.
				resource.TestCheckResourceAttr(allVersions, "matched", "2"),
				resource.TestCheckResourceAttr(allVersions, "keys.#", "2"),

				// version = -1 returns only the latest version, which is the pfx upload.
				resource.TestCheckResourceAttr(latest, "matched", "1"),
				resource.TestCheckResourceAttr(latest, "keys.#", "1"),
				resource.TestCheckResourceAttrPair(latest, "keys.0.id", pfxResource, "id"),
				resource.TestCheckResourceAttrPair(latest, "keys.0.kid", pfxResource, "azure_params.key.kid"),
				resource.TestCheckResourceAttr(latest, "keys.0.name", keyName),

				// The lower case algorithm matches both RSA versions.
				resource.TestCheckResourceAttr(rsaAlgorithm, "matched", "2"),
				resource.TestCheckResourceAttr(rsaAlgorithm, "keys.#", "2"),
				resource.TestCheckResourceAttr(rsaAlgorithm, "keys.0.kty", "RSA"),
				resource.TestCheckResourceAttrPair(latest, "keys.0.vault_id", vaultResource, "id"),
			),
		})
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: append([]resource.TestStep{
			// Step 1: upload the CipherTrust Manager key.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    createConfigStr,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrPair(keyResource, "vault_id", vaultResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
					resource.TestCheckResourceAttr(keyResource, "upload_key.source_key_tier", "local"),
					resource.TestCheckResourceAttrPair(keyResource, "upload_key.source_key_id", "ciphertrust_cm_key.cm_rsa_key", "id"),
					resource.TestCheckResourceAttr(keyResource, "upload_key.local_key_name", cmKeyName),
					resource.TestCheckResourceAttrSet(keyResource, "vault_name"),
					resource.TestCheckResourceAttrSet(keyResource, "azure_params.key.kid"),
					resource.TestCheckResourceAttrSet(keyResource, "created_at"),
					resource.TestCheckResourceAttrSet(keyResource, "updated_at"),
					resource.TestCheckResourceAttr(keyResource, "deleted", "false"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "6"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.activation_date", activationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", expirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey2", "TagValue2"),
				),
			},
			// Step 2: update tags, key_ops, enabled and the dates.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 2") },
				Config:    updateConfigStr,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.activation_date", newActivationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", newExpirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey2", "TagValue2Updated"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey3", "TagValue3"),
					resource.TestCheckNoResourceAttr(keyResource, "azure_params.tags.TagKey1"),
				),
			},
			// Step 3: import.
			{
				PreConfig:               func() { logTestStep(t.Name(), "Step 3 import") },
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAzureKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			// Step 4: back to the key creation values with tags = {}.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 4") },
				Config:    resetConfigStr,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "6"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.activation_date", activationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", expirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "0"),
				),
			},
			// Steps 4e to 4g: optional attributes are removed from the config one at a time. Terraform keeps
			// the current value in Azure, so each removed attribute keeps the value it had. The steps build on
			// each other: tags are set again in 4e so that 4g can show they are kept.
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 4e remove key_ops") },
				Config:    optionalConfigStr("", expirationLine, createTags),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "6"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", expirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
				),
			},
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 4f remove expiration_date") },
				Config:    optionalConfigStr("", "", createTags),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "6"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", expirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
				),
			},
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 4g remove tags") },
				Config:    optionalConfigStr("", "", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "azure_params.key.key_ops.#", "6"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.attributes.expiration_date", expirationDate),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "azure_params.tags.TagKey1", "TagValue1"),
				),
			},
			// Steps 4a to 4d: each immutable input is changed in turn. The plan is rejected, so nothing
			// is sent to Azure and the key is unchanged.
			{
				PreConfig:   func() { logTestStep(t.Name(), "Step 4a immutable vault_id") },
				Config:      immutableConfigStr(`"00000000-0000-0000-0000-000000000000"`, keyName, "local", localKeyExpr),
				ExpectError: immutableError,
			},
			{
				PreConfig:   func() { logTestStep(t.Name(), "Step 4b immutable name") },
				Config:      immutableConfigStr(vaultExpr, keyName+"-changed", "local", localKeyExpr),
				ExpectError: immutableError,
			},
			{
				PreConfig:   func() { logTestStep(t.Name(), "Step 4c immutable upload_key.source_key_tier") },
				Config:      immutableConfigStr(vaultExpr, keyName, "pfx", localKeyExpr),
				ExpectError: immutableError,
			},
			{
				PreConfig:   func() { logTestStep(t.Name(), "Step 4d immutable upload_key.source_key_id") },
				Config:      immutableConfigStr(vaultExpr, keyName, "local", `"another-cm-key-id"`),
				ExpectError: immutableError,
			},
		}, pfxUploadSteps...),
	})
}

// azureProviderSettingsConfig returns config with the Azure key delete settings added to the provider
// block. The settings in the config of a test run apply to every key destroyed at the end of that run.
func azureProviderSettingsConfig(config string, purgeKeysOnDelete, recoverSoftDeletedKeys, retainKeyBackupsAfterPurge bool) string {
	settings := fmt.Sprintf(`provider "ciphertrust" {
		cloud_key_manager = {
			azure = {
				purge_keys_on_delete           = %t
				recover_soft_deleted_keys      = %t
				retain_key_backups_after_purge = %t
			}
		}`, purgeKeysOnDelete, recoverSoftDeletedKeys, retainKeyBackupsAfterPurge)
	return strings.Replace(config, `provider "ciphertrust" {`, settings, 1)
}

// TestCckmAzureKeyUploadValidation checks the upload_key configuration errors that are raised at plan time.
// No Azure calls are made and no keys are created, so the vault_id values are literals. Terraform wraps long
// error text, so the patterns use \s+ between words.
func TestCckmAzureKeyUploadValidation(t *testing.T) {
	// uploadConfig wraps the body of a ciphertrust_azure_key resource.
	uploadConfig := func(body string) string {
		return `
			resource "ciphertrust_azure_key" "upload_key" {
				vault_id = "00000000-0000-0000-0000-000000000000"
				name     = "tf-validation"
				` + body + `
			}`
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: upload_key = {} has no source_key_tier.
			{
				Config:      uploadConfig(`upload_key = {}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`source_key_tier`),
			},
			// Step 2: only hsm is set.
			{
				Config:      uploadConfig(`upload_key = { hsm = true }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`source_key_tier`),
			},
			// Step 3: local without source_key_id.
			{
				Config:      uploadConfig(`upload_key = { source_key_tier = "local" }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`source_key_id\s+is\s+required`),
			},
			// Step 4: pfx without pfx.
			{
				Config:      uploadConfig(`upload_key = { source_key_tier = "pfx" }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`upload_key.pfx\s+is\s+required`),
			},
			// Step 5: pfx set with source_key_tier local.
			{
				Config: uploadConfig(`upload_key = {
					source_key_tier = "local"
					source_key_id   = "some-cm-key-id"
					pfx             = "/tmp/not-used.pfx"
				}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`pfx\s+can\s+only\s+be\s+set`),
			},
			// Step 6: pfx_password set with source_key_tier local.
			{
				Config: uploadConfig(`upload_key = {
					source_key_tier = "local"
					source_key_id   = "some-cm-key-id"
					pfx_password    = "secret"
				}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`pfx_password\s+can\s+only\s+be\s+set`),
			},
			// Step 7: source_key_id set with source_key_tier pfx.
			{
				Config: uploadConfig(`upload_key = {
					source_key_tier = "pfx"
					pfx             = "/tmp/not-used.pfx"
					source_key_id   = "some-cm-key-id"
				}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`source_key_id\s+cannot\s+be\s+set`),
			},
			// Step 8: invalid source_key_tier.
			{
				Config: uploadConfig(`upload_key = {
					source_key_tier = "other"
					source_key_id   = "some-cm-key-id"
				}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`must\s+be\s+one\s+of`),
			},
			// Step 9: kty is set with upload_key.
			{
				Config: uploadConfig(`upload_key = {
					source_key_tier = "local"
					source_key_id   = "some-cm-key-id"
				}
				azure_params = {
					key = {
						kty = "RSA"
					}
				}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`kty\s+cannot\s+be\s+set`),
			},
			// Step 10: key_size is set with upload_key.
			{
				Config: uploadConfig(`upload_key = {
					source_key_tier = "local"
					source_key_id   = "some-cm-key-id"
				}
				azure_params = {
					key_size = 2048
				}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`key_size\s+cannot\s+be\s+set`),
			},
			// Step 11: upload_key and restore_key together.
			{
				Config: `
					resource "ciphertrust_azure_key" "upload_key" {
						vault_id = "00000000-0000-0000-0000-000000000000"
						restore_key = {
							key_id = "some-key-id"
						}
						upload_key = {
							source_key_tier = "local"
							source_key_id   = "some-cm-key-id"
						}
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`upload_key\s+cannot\s+be\s+set`),
			},
		},
	})
}

// TestCckmAzureKeyPurgeableVault covers every purgeable vault scenario with two keys in total, so the vault is
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
// It needs CCKM_TF_AZURE_PURGEABLE_VAULT. CCKM_TF_AZURE_RELEASE_POLICY (a JSON object string) is optional. When
// it is not set, key 1 is created without exportable and release_policy, and those attributes are not checked.
func TestCckmAzureKeyPurgeableVault(t *testing.T) {
	initConfig, ok := initCckmAzureTestPurgeableVault()
	if !ok {
		t.Skip("Azure environment variables or CCKM_TF_AZURE_PURGEABLE_VAULT not set - skipping TestCckmAzureKeyPurgeableVault")
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

	purgeableVaultResource := "ciphertrust_azure_vault.purgeable_vault"
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
			vault_id = ciphertrust_azure_vault.purgeable_vault.id
			name     = %q
			upload_key = {
				source_key_tier = "local"
				source_key_id   = ciphertrust_cm_key.cm_rsa_key.id
				hsm             = true
			}
			%s
		}`, cmKeyName, uploadKeyName, policyAttrs)

	// uploadChainFailed is set when a subtest of the uploaded key chain fails. The later subtests of the chain
	// use the key and the backups of the earlier ones, so they are skipped. The PIT chain is independent.
	uploadChainFailed := false
	t.Run("upload_hsm_key", func(t *testing.T) {
		defer func() { uploadChainFailed = uploadChainFailed || t.Failed() }()
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					PreConfig: func() { logTestStep(t.Name(), "Upload exportable HSM key, destroy with purge and retain") },
					Config:    azureProviderSettingsConfig(initConfig+uploadConfig, true, false, true),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(uploadResource, "id"),
						resource.TestCheckResourceAttrPair(uploadResource, "vault_id", purgeableVaultResource, "id"),
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
		defer func() { uploadChainFailed = uploadChainFailed || t.Failed() }()
		if uploadChainFailed {
			t.Skip("an earlier uploaded key subtest failed - skipping restore_soft_delete_only")
		}
		if uploadKeyID == "" {
			t.Skip("key ID was not captured - skipping restore_soft_delete_only")
		}
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "restored_key" {
				vault_id = ciphertrust_azure_vault.purgeable_vault.id
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
						resource.TestCheckResourceAttrPair(restoredResource, "vault_id", purgeableVaultResource, "id"),
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
		defer func() { uploadChainFailed = uploadChainFailed || t.Failed() }()
		if uploadChainFailed {
			t.Skip("an earlier uploaded key subtest failed - skipping recover_purge_delete_backups")
		}
		if uploadKeyID == "" {
			t.Skip("key ID was not captured - skipping recover_purge_delete_backups")
		}
		// A native key is used because only ciphertrust_azure_key recovers a soft-deleted key of the same name.
		recoverConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "native_key" {
				vault_id = ciphertrust_azure_vault.purgeable_vault.id
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
						resource.TestCheckResourceAttrPair(nativeResource, "vault_id", purgeableVaultResource, "id"),
						resource.TestCheckResourceAttr(nativeResource, "name", uploadKeyName),
						policyCheck(nativeResource),
					),
				},
			},
		})
	})

	t.Run("restore_after_backups_deleted", func(t *testing.T) {
		if uploadChainFailed {
			t.Skip("an earlier uploaded key subtest failed - skipping restore_after_backups_deleted")
		}
		if uploadKeyID == "" {
			t.Skip("key ID was not captured - skipping restore_after_backups_deleted")
		}
		backupLine := ""
		if uploadBackupID != "" {
			backupLine = fmt.Sprintf("backup_id = %q", uploadBackupID)
		}
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "restored_key" {
				vault_id = ciphertrust_azure_vault.purgeable_vault.id
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
			vault_id = ciphertrust_azure_vault.purgeable_vault.id
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

	// pitBackupFailed is set when create_pit_backup fails, so that restore_from_pit_backup is skipped.
	pitBackupFailed := false
	t.Run("create_pit_backup", func(t *testing.T) {
		defer func() { pitBackupFailed = t.Failed() }()
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
		if pitBackupFailed {
			t.Skip("create_pit_backup failed - skipping restore_from_pit_backup")
		}
		if pitKeyID == "" || pitBackupID == "" {
			t.Fatal("key or backup ID was not captured by create_pit_backup, which always creates a PIT backup")
		}
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_key" "restored_key" {
				vault_id = ciphertrust_azure_vault.purgeable_vault.id
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
						resource.TestCheckResourceAttrPair(restoredResource, "vault_id", purgeableVaultResource, "id"),
						resource.TestCheckResourceAttr(restoredResource, "name", pitKeyName),
						resource.TestCheckResourceAttr(restoredResource, "restore_key.key_id", pitKeyID),
						resource.TestCheckResourceAttr(restoredResource, "restore_key.backup_id", pitBackupID),
					),
				},
			},
		})
	})
}
