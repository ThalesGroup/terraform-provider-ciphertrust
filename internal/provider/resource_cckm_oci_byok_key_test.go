// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

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

// importStateVerifyIgnoreOCIKey lists attributes that cannot round-trip through terraform import
// for an OCI key (both native and BYOK). Used by import steps in TestCckmOCIByokKey
// and TestCckmOCIKeyNative.
var importStateVerifyIgnoreOCIKey = []string{
	// version_summary: Computed list; reflects versions present at key-read time, not
	// at import time -- may have changed between the two operations.
	"version_summary",
	// oci_key_params.current_key_version: Computed; changes as new versions are promoted.
	"oci_key_params.current_key_version",
	// schedule_for_deletion_days: Optional+Computed with retainOrDefaultInt64 plan modifier;
	// not returned from the API so it is null in post-import state even if non-null pre-import.
	"schedule_for_deletion_days",
}

func getOCIKeyVersionID(keyResourceName string, versionResourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[keyResourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", keyResourceName)
		}
		keyID, ok := rs.Primary.Attributes["id"]
		if !ok {
			return "", fmt.Errorf("id not found in state for %s", keyResourceName)
		}
		rs, ok = s.RootModule().Resources[versionResourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", versionResourceName)
		}
		versionID, ok := rs.Primary.Attributes["id"]
		if !ok {
			return "", fmt.Errorf("id not found in state for %s", versionResourceName)
		}
		return keyID + "." + versionID, nil
	}
}

// TestCckmOCIByokKey is a comprehensive lifecycle test for ciphertrust_oci_byok_key and
// ciphertrust_oci_byok_key_version that covers:
//
//   - Create with tags, schedule_for_deletion_days, and data source checks.
//   - ModifyPlan immutability rejections: source_key_id and cckm_key_id both produce a
//     plan-time error when changed after creation.
//   - Refresh and import (key and version).
//   - Update lifecycle: disable/re-enable, freeform and defined tags, rename, scheduler
//     add/change/remove.
//   - OOB version deletion: RefreshState retains version as SCHEDULING_DELETION; Update
//     (schedule_for_deletion_days) retains with warning.
//   - OOB key deletion: RefreshState retains key as SCHEDULING_DELETION (drift reported);
//     Update triggers "Provider produced inconsistent result".
func TestCckmOCIByokKey(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	localsConfig := `locals {
		cm_key_name         = "tf-%s"
		cm_key_version_name = "tf-%s"
		rotation_job_name   = "tf-%s"
		rotation_job_name_2 = "tf-%s"
	}`

	localsResource := fmt.Sprintf(localsConfig,
		uuid.New().String()[:8], uuid.New().String()[:8],
		uuid.New().String()[:8], uuid.New().String()[:8])

	keyName := "tf-" + uuid.New().String()[:8]
	keyNameUpdate := "tf-" + uuid.New().String()[:8]

	schedulersConfig := `
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
		}`

	enableRotationConfig := `
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_1.id
				key_source    = "ciphertrust"
			}`

	updateEnableRotationConfig := `
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_2.id
				key_source    = "ciphertrust"
			}`

	tagsConfig := `
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
		}`

	updateTagsConfig := `
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
		}`

	removeTagsConfig := `
		defined_tags = []
		freeform_tags = {}
	`

	createConfig := `
		# Place holder for schedulers
		%s
		# Create an AES CipherTrust key
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
		}

		# Create a byok OCI key
		resource "ciphertrust_oci_byok_key" "aes" {
			name                       = "%s"
			schedule_for_deletion_days = %d
            enable_key                 = %t
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
				# Place holder for tags
				%s
			}
			source_key_id   = %s
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
			# Place holder for enable_rotation
			%s
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
			schedule_for_deletion_days = %d
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

	// Creates keys and versons - scheduled_for_deletion in 10 days
	createResourceStr := localsResource + connectionResource +
		fmt.Sprintf(createConfig, "\n", keyName, 10, true, tagsConfig,
			"ciphertrust_cm_key.cm_aes_key.id", "\n", "ciphertrust_oci_byok_key.aes.id", 10)

	// modifyKeyConfigStr: source_key_id changed to a fake value - triggers plan-time immutability error.
	modifyKeyConfigStr := localsResource + connectionResource +
		fmt.Sprintf(createConfig, "\n", keyName, 10, true, tagsConfig,
			`"tf-fake-source-key-id"`, "\n", "ciphertrust_oci_byok_key.aes.id", 10)

	// modifyVersionConfigStr: cckm_key_id on byok_v1 changed to a fake value - triggers plan-time error.
	modifyVersionConfigStr := localsResource + connectionResource +
		fmt.Sprintf(createConfig, "\n", keyName, 10, true, tagsConfig,
			"ciphertrust_cm_key.cm_aes_key.id", "\n", `"tf-fake-key-id"`, 10)

	// Update key - add tags and scheduler and change deletion days to 7
	updateResourceStr := localsResource + connectionResource +
		fmt.Sprintf(createConfig, schedulersConfig, keyName, 7, false, tagsConfig,
			"ciphertrust_cm_key.cm_aes_key.id", enableRotationConfig, "ciphertrust_oci_byok_key.aes.id", 7)
	updateResourceStr = applyCDSPAAS(updateResourceStr)

	// Update tags and name and change scheduler
	updateResourceStr2 := localsResource + connectionResource +
		fmt.Sprintf(createConfig, schedulersConfig, keyNameUpdate, 7, true, updateTagsConfig,
			"ciphertrust_cm_key.cm_aes_key.id", updateEnableRotationConfig, "ciphertrust_oci_byok_key.aes.id", 7)
	updateResourceStr2 = applyCDSPAAS(updateResourceStr2)

	// Remove tags and scheduler
	updateResourceStr3 := localsResource + connectionResource +
		fmt.Sprintf(createConfig, "\n", keyNameUpdate, 7, true, removeTagsConfig,
			"ciphertrust_cm_key.cm_aes_key.id", "\n", "ciphertrust_oci_byok_key.aes.id", 7)

	// Update name, remove empty tags
	updateResourceStr4 := localsResource + connectionResource +
		fmt.Sprintf(createConfig, "\n", keyName, 7, true, "\n",
			"ciphertrust_cm_key.cm_aes_key.id", "\n", "ciphertrust_oci_byok_key.aes.id", 7)

	keyResource := "ciphertrust_oci_byok_key.aes"
	versionResource := "ciphertrust_oci_byok_key_version.byok_v1"
	keysDataSource := "data.ciphertrust_oci_key_list.keys"
	versionDataSource := "data.ciphertrust_oci_key_version_list.versions"
	schedulerResource1 := "ciphertrust_scheduler.scheduler_1"
	schedulerResource2 := "ciphertrust_scheduler.scheduler_2"

	var capturedByokKeyID, capturedByokV1ID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a valid key + versions; verify attributes and data sources.
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttrPair(keyResource, "source_key_id", "ciphertrust_cm_key.cm_aes_key", "id"),
					resource.TestCheckResourceAttr(keyResource, "source_key_tier", "local"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttrPair(keyResource, "vault", "ciphertrust_oci_vault.vault", "id"),
					resource.TestCheckResourceAttrSet(keyResource, "oci_key_params.key_id"),
					resource.TestCheckResourceAttrSet(keyResource, "vault_id"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "10"),
					// version_summary reflects versions present at key-read time (not later-added versions in same apply)
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.bonjour", "french"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.hello", "english"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.defined_tags.#", "2"),
					// Version resource (byok_v1)
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "10"),
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
				// Step 2: ModifyPlan - source_key_id changed, expect plan-time immutability error.
				Config:      modifyKeyConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
			{
				// Step 3: ModifyPlan - cckm_key_id changed on byok_v1, expect plan-time immutability error.
				Config:      modifyVersionConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
			{
				// Step 4: re-apply createResourceStr to reset the framework's current config after
				// the PlanOnly steps. This prevents the stale modifyVersionConfigStr from being
				// used as the consistency plan config in the RefreshState step that follows.
				Config: createResourceStr,
			},
			{
				// Step 5: refresh state after create.
				RefreshState: true,
			},
			{
				// Step 6: import the key resource.
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreOCIKey,
			},
			{
				// Step 7: import the key version resource.
				ResourceName:      versionResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"schedule_for_deletion_days",
					// source_key_id is reconstructed from the version list on read; may not
					// round-trip exactly after import if the version order differs.
					"source_key_id",
				},
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, versionResource),
			},
			{
				// Step 8: disable key + enable scheduler_1 rotation + update tags.
				// schedule_for_deletion_days reduced to 7 for both key and version.
				Config: updateResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "name", keyName),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "DISABLED"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					resource.TestCheckResourceAttrPair(keyResource, "labels.job_config_id", schedulerResource1, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.bonjour", "french"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.hello", "english"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.defined_tags.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "7"),
				),
			},
			{
				// Step 9: re-enable key + switch rotation to scheduler_2 + update tags + rename.
				Config: updateResourceStr2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "name", keyNameUpdate),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					resource.TestCheckResourceAttrPair(keyResource, "labels.job_config_id", schedulerResource2, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.%", "1"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.bonjour", "french"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.defined_tags.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
				),
			},
			{
				// Step 10: remove schedulers, key rotation, and tags.
				// Capture key and byok_v1 IDs for the OOB deletion steps that follow.
				Config: updateResourceStr3,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "name", keyNameUpdate),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.defined_tags.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found: %s", keyResource)
						}
						capturedByokKeyID = rs.Primary.ID
						return nil
					},
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found: %s", versionResource)
						}
						capturedByokV1ID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 11: OOB version deletion - RefreshState: schedule byok_v1 for deletion out-of-band,
				// then refresh state. Expected: byok_v1 retained with SCHEDULING_DELETION.
				PreConfig: func() {
					scheduleOciKeyVersionDeletionOutOfBand(capturedByokKeyID, capturedByokV1ID)
				},
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found: %s", versionResource)
						}
						if rs.Primary.ID != capturedByokV1ID {
							return fmt.Errorf("expected v1 id %q, got %q", capturedByokV1ID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(versionResource, "oci_key_version_params.lifecycle_state", "SCHEDULING_DELETION"),
					resource.TestCheckResourceAttr("ciphertrust_oci_byok_key_version.byok_v2", "oci_key_version_params.lifecycle_state", "ENABLED"),
				),
			},
			{
				// Step 12: OOB version deletion - Update: apply schedule_for_deletion_days = 10 on byok_v1.
				// byok_v1 is already SCHEDULING_DELETION. Expected: warning issued, byok_v1 retained.
				Config: updateResourceStr4,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found: %s", versionResource)
						}
						if rs.Primary.ID != capturedByokV1ID {
							return fmt.Errorf("expected v1 id %q, got %q", capturedByokV1ID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(versionResource, "oci_key_version_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
			{
				// Step 13: OOB key deletion - RefreshState: schedule the key itself for deletion out-of-band.
				// OCI auto-disables the key, causing drift on enable_key - ExpectNonEmptyPlan captures this.
				// Expected: key retained with lifecycle_state = SCHEDULING_DELETION.
				PreConfig: func() {
					scheduleOciKeyDeletionOutOfBand(capturedByokKeyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found: %s", keyResource)
						}
						if rs.Primary.ID != capturedByokKeyID {
							return fmt.Errorf("expected key id %q, got %q", capturedByokKeyID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
			{
				// Step 14: OOB key deletion - Update: apply a name change on the SCHEDULING_DELETION key.
				// OCI auto-disables the key, so enable_key in the post-apply read-back is false,
				// but the plan used the schema default (true). The Terraform framework raises
				// "Provider produced inconsistent result".
				Config:      updateResourceStr2,
				ExpectError: regexp.MustCompile("Provider produced inconsistent result"),
			},
		},
	})
}

// TestCckmOCIByokKeyRestoreFromBackup verifies that setting restore_from_backup_trigger on a
// BYOK OCI key triggers a restore from the most recent OCI backup.
// Applicable only to HSM-protected keys in OCI Virtual Private Vaults.
// Skipped if CCKM_OCI_VP_VAULT_OCID is not set.
func TestCckmOCIByokKeyRestoreFromBackup(t *testing.T) {
	vpVaultOCID := os.Getenv("CCKM_OCI_VP_VAULT_OCID")
	if vpVaultOCID == "" {
		t.Skip("CCKM_OCI_VP_VAULT_OCID not set")
	}

	connectionResource := initCckmOCITest(t)

	// List buckets accessible from the standard vault's compartment so the VP vault
	// can be configured with bucket storage, which is required for HSM key backup/restore.
	// Register the virtual private vault alongside the standard vault.
	vpVaultResource := fmt.Sprintf(`
		data "ciphertrust_get_oci_buckets" "buckets" {
			connection_id  = ciphertrust_oci_connection.oci_connection.id
			compartment_id = ciphertrust_oci_vault.vault.compartment_id
			limit          = 1
		}

		resource "ciphertrust_oci_vault" "vp_vault" {
			connection_id    = ciphertrust_oci_connection.oci_connection.id
			vault_id         = "%s"
			region           = local.region
			bucket_name      = data.ciphertrust_get_oci_buckets.buckets.buckets[0].name
			bucket_namespace = data.ciphertrust_get_oci_buckets.buckets.buckets[0].namespace
		}`, vpVaultOCID)

	baseConfig := connectionResource + vpVaultResource

	cmKeyName := "tf-" + uuid.New().String()[:8]
	cmVersionKeyName := "tf-" + uuid.New().String()[:8]
	ociKeyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_byok_key.key"
	versionResource := "ciphertrust_oci_byok_key_version.version"

	createConfig := fmt.Sprintf(`
			resource "ciphertrust_cm_key" "cm_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_cm_key" "cm_version_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_oci_byok_key" "key" {
				name = "%s"
				oci_key_params = {
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					protection_mode = "HSM"
				}
				source_key_id   = ciphertrust_cm_key.cm_key.id
				source_key_tier = "local"
				vault           = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_byok_key_version" "version" {
				cckm_key_id   = ciphertrust_oci_byok_key.key.id
				source_key_id = ciphertrust_cm_key.cm_version_key.id
			}`, cmKeyName, cmVersionKeyName, ociKeyName)

	restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_cm_key" "cm_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_cm_key" "cm_version_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_oci_byok_key" "key" {
				name = "%s"
				oci_key_params = {
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					protection_mode = "HSM"
				}
				restore_from_backup_trigger = "1"
				source_key_id   = ciphertrust_cm_key.cm_key.id
				source_key_tier = "local"
				vault           = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_byok_key_version" "version" {
				cckm_key_id   = ciphertrust_oci_byok_key.key.id
				source_key_id = ciphertrust_cm_key.cm_version_key.id
			}`, cmKeyName, cmVersionKeyName, ociKeyName)

	var capturedVersionUpdatedAt string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create an HSM-protected BYOK key and a BYOK version on the VP vault.
				Config: baseConfig + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "HSM"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", versionResource)
						}
						capturedVersionUpdatedAt = rs.Primary.Attributes["updated_at"]
						return nil
					},
				),
			},
			{
				// Step 2: set restore_from_backup_trigger to trigger a restore from backup.
				// Verify the trigger attribute is reflected in state.
				Config: baseConfig + restoreConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "restore_from_backup_trigger", "1"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
				),
			},
			{
				// Step 3: refresh state to re-read version attributes from the API,
				// then verify updated_at changed after the restore.
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", versionResource)
						}
						newUpdatedAt := rs.Primary.Attributes["updated_at"]
						if capturedVersionUpdatedAt != "" && newUpdatedAt == capturedVersionUpdatedAt {
							return fmt.Errorf("expected version updated_at to change after restore, got same value: %s", newUpdatedAt)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestCckmOCIByokInvalidCreateConfigs(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	localsConfig := `locals {
		cm_key_name      = "tf-%s"
		oci_key_name     = "tf-%s"
		rotation_job_name = "tf-%s"
		source_key_tier  = "local"
	}`

	localsResource := fmt.Sprintf(localsConfig,
		uuid.New().String()[:8], uuid.New().String()[:8],
		uuid.New().String()[:8])

	// disableAtCreateConfig: enable_key = false at create - rejected by ModifyPlan.
	disableAtCreateConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name       = local.cm_key_name
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		resource "ciphertrust_oci_byok_key" "aes" {
			enable_key    = false
			name         = local.oci_key_name
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = local.source_key_tier
			vault           = ciphertrust_oci_vault.vault.id
		}`

	// schedulerAtCreateConfig: enable_auto_rotation at create - rejected by ModifyPlan.
	schedulerAtCreateConfig := `
		resource "ciphertrust_scheduler" "scheduler_at_create" {
			end_date = "2050-03-07T14:24:00Z"
			cckm_key_rotation_params = {
				cloud_name = "oci"
			}
			name       = local.rotation_job_name
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}

		resource "ciphertrust_cm_key" "cm_aes_key" {
			name       = local.cm_key_name
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		resource "ciphertrust_oci_byok_key" "aes" {
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_at_create.id
				key_source    = "ciphertrust"
			}
			name          = local.oci_key_name
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = local.source_key_tier
			vault           = ciphertrust_oci_vault.vault.id
		}`

	// disableAtCreateStr: enable_key = false at create - plan-time rejection test.
	disableAtCreateStr := localsResource + connectionResource + disableAtCreateConfig

	// schedulerAtCreateStr: enable_auto_rotation at create - plan-time rejection test.
	schedulerAtCreateStr := applyCDSPAAS(localsResource + connectionResource + schedulerAtCreateConfig)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: enable_key = false at create must be rejected at plan time.
				Config:      disableAtCreateStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid create-time attribute`),
			},
			{
				// Step 2: enable_auto_rotation at create must be rejected at plan time.
				Config:      schedulerAtCreateStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid create-time attribute`),
			},
		},
	})
}
