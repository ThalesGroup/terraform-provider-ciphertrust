package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// importStateVerifyIgnoreOCIKey lists attributes that cannot round-trip through terraform import
// for an OCI key (both native and BYOK). Used by import steps in TestCckmOCIKeysAndVersionsBYOK
// and TestCckmOCIKeysAndVersionsNative.
var importStateVerifyIgnoreOCIKey = []string{
	// version_summary: Computed list; reflects versions present at key-read time, not
	// at import time -- may have changed between the two operations.
	"version_summary",
	// oci_key_params.current_key_version: Computed; changes as new versions are promoted.
	"oci_key_params.current_key_version",
	// schedule_for_deletion_days: Optional-only on the key schema (no Computed/default);
	// stays null in both pre-import and post-import state, but kept here for explicitness.
	"schedule_for_deletion_days",
}

func TestCckmOCIKeysAndVersionsBYOK(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	localsConfig := `locals {
		cm_key_name         = "tf-%s"
		oci_key_name        = "tf-%s"
		cm_key_version_name = "tf-%s"
		rotation_job_name   = "tf-%s"
		rotation_job_name_2 = "tf-%s"
		oci_key_name_update = "tf-%s"
	}`

	localsResource := fmt.Sprintf(localsConfig,
		uuid.New().String()[:8], uuid.New().String()[:8], uuid.New().String()[:8],
		uuid.New().String()[:8], uuid.New().String()[:8], uuid.New().String()[:8])

	maxConfig := `
		%s
		%s

		# Create a rotation scheduler
		resource "ciphertrust_scheduler" "scheduler_1" {
			end_date = "2050-03-07T14:24:00Z"
			cckm_key_rotation_params = {
				cloud_name       = "oci"
			}
			name       = local.rotation_job_name
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}

		# Create an AES CipherTrust key
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
		}

		# Create a byok OCI key
		resource "ciphertrust_oci_byok_key" "aes" {
			enable_key = true
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_1.id
				key_source    = "ciphertrust"
			}
			name            = local.oci_key_name
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
				defined_tags = [
					{
						tag = "CCKM_OCI_1"
						values = {
							"TagKey1" = "TagValue1"
							"TagKey2" = "TagValue2"
						}
					},
					{
					tag = "CCKM_OCI"
						values = {
							"CCKM_OCI_Tag_1" = "cckmocitag1"
							"CCKM_OCI_Tag_2" = "cckmocitag2"
							"CCKM_OCI_Tag_3" = "cckmocitag3"
						}
					}
				]
				freeform_tags = {
					bonjour = "french"
					hello = "english"
				}
			}
			source_key_id   = %s
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		# Create an AES CipherTrust key for the key version
		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		# Add a byok version to the key
		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id = %s
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add another byok version
		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "native_v1" {
			# Make this version the current version
			depends_on = [ciphertrust_oci_byok_key_version.byok_v1, ciphertrust_oci_byok_key_version.byok_v2]
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}

		# List the key
		data "ciphertrust_oci_key_list" "keys" {
			depends_on = [ciphertrust_oci_key_version.native_v1]
			filters = {
				key_name = ciphertrust_oci_byok_key.aes.name
			}
		}

		# List the key's versions
		data "ciphertrust_oci_key_version_list" "versions" {
			key_id = ciphertrust_oci_byok_key.aes.id
			depends_on = [ciphertrust_oci_key_version.native_v1]
		}`

	updateConfig := `
		%s
		%s

		# Create a rotation scheduler
		resource "ciphertrust_scheduler" "scheduler_1" {
			end_date = "2050-03-07T14:24:00Z"
			cckm_key_rotation_params = {
				cloud_name       = "oci"
			}
			name       = local.rotation_job_name
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}

		resource "ciphertrust_scheduler" "scheduler_2" {
			end_date = "2050-03-07T14:24:00Z"
			cckm_key_rotation_params = {
			cloud_name       = "oci"
			}
			name       = local.rotation_job_name_2
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}

		# Create an AES CipherTrust key
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
		}

		# Create a byok OCI key
		resource "ciphertrust_oci_byok_key" "aes" {
			enable_key = true
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_2.id
				key_source    = "ciphertrust"
			}
			name            = local.oci_key_name_update
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
				defined_tags = [
					{
						tag = "CCKM_OCI_1"
						values = {
							"TagKey3" = "TagValue3"
						}
					},
					{
						tag = "CCKM_OCI"
						values = {
							"CCKM_OCI_Tag_3" = "cckmocitag3"
							"CCKM_OCI_Tag_4" = "cckmocitag4"
						}
					}
				]
				freeform_tags = {
					bonjour = "french"
					ciao = "italian"
				}
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		# Create an AES CipherTrust key for the key version
		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		# Add a byok version to the key
		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add another byok version
		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "native_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}`

	minConfig := `
		%s
		%s

		# Create an AES CipherTrust key
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
		}

		# Create a byok OCI key
		resource "ciphertrust_oci_byok_key" "aes" {
			name            = local.oci_key_name
			oci_key_params = {
				protection_mode = "SOFTWARE"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		# Create an AES CipherTrust key for the key version
		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		# Add a byok version to the key
		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add another byok version
		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "native_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}`

	keyResource := "ciphertrust_oci_byok_key.aes"
	versionResource := "ciphertrust_oci_byok_key_version.byok_v1"
	keysDataSource := "data.ciphertrust_oci_key_list.keys"
	versionDataSource := "data.ciphertrust_oci_key_version_list.versions"

	maxConfig = applyCDSPAAS(maxConfig)
	updateConfig = applyCDSPAAS(updateConfig)
	createResourceStr := fmt.Sprintf(maxConfig, localsResource, connectionResource,
		"ciphertrust_cm_key.cm_aes_key.id", "ciphertrust_oci_byok_key.aes.id")
	updateResourceStr := fmt.Sprintf(updateConfig, localsResource, connectionResource)
	minResourceStr := fmt.Sprintf(minConfig, localsResource, connectionResource)
	modifyKeyConfigStr := fmt.Sprintf(maxConfig, localsResource, connectionResource,
		`"tf-fake-source-key-id"`, "ciphertrust_oci_byok_key.aes.id")
	modifyVersionConfigStr := fmt.Sprintf(maxConfig, localsResource, connectionResource,
		"ciphertrust_cm_key.cm_aes_key.id", `"tf-fake-key-id"`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "source_key_tier", "local"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttrPair(keyResource, "vault", "ciphertrust_oci_vault.vault", "id"),
					resource.TestCheckResourceAttrSet(keyResource, "oci_key_params.key_id"),
					resource.TestCheckResourceAttrSet(keyResource, "vault_id"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					// version_summary reflects versions present at key-read time (not later-added versions in same apply)
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					// Version resource (byok_v1)
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
					// Key list data source
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					resource.TestCheckResourceAttr(keysDataSource, "matched", "1"),
					resource.TestCheckResourceAttrPair(keysDataSource, "keys.0.id", keyResource, "id"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.0.oci_key_params.protection_mode", "SOFTWARE"),
					// Key version list data source
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "4"),
					resource.TestCheckResourceAttr(versionDataSource, "matched", "4"),
					resource.TestCheckResourceAttrSet(versionDataSource, "versions.0.id"),
				),
			},
			{
				RefreshState: true,
			},
			{
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreOCIKey,
			},
			{
				ResourceName:      versionResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, versionResource),
			},
			{
				Config: updateResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource -- scheduler switched to scheduler_2, name changed to oci_key_name_update
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
				),
			},
			{
				// Get the key deleted
				Config: connectionResource,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: minResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource -- no rotation, no tags, default enable_key (true)
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "source_key_tier", "local"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
				),
			},
			{
				RefreshState: true,
			},
			{
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreOCIKey,
			},
			{
				ResourceName:      versionResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, versionResource),
			},
			{
				Config: updateResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
				),
			},
			{
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					// Key list data source
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					// Key version list data source
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "4"),
				),
			},
			// ModifyPlan: source_key_id changed to a fake value - expect plan-time error on byok key.
			{
				Config:      modifyKeyConfigStr,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
			// ModifyPlan: cckm_key_id changed to a fake value - expect plan-time error on byok key version.
			{
				Config:      modifyVersionConfigStr,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
		},
	})
}

func getOCIKeyVersionID(keyResourceName string, versionResourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[keyResourceName]
		if !ok {
			return "", fmt.Errorf("not found: " + keyResourceName)
		}
		keyID, ok := rs.Primary.Attributes["id"]
		if !ok {
			return "", fmt.Errorf("id not found in state for " + keyResourceName)
		}
		rs, ok = s.RootModule().Resources[versionResourceName]
		if !ok {
			return "", fmt.Errorf("not found: " + versionResourceName)
		}
		versionID, ok := rs.Primary.Attributes["id"]
		if !ok {
			return "", fmt.Errorf("id not found in state for " + versionResourceName)
		}
		return keyID + "." + versionID, nil
	}
}
