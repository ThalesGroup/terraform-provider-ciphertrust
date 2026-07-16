package provider

import (
	"fmt"
	"regexp"
	"strings"
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
	// schedule_for_deletion_days: Optional+Computed with retainOrDefaultInt64 plan modifier;
	// not returned from the API so it is null in post-import state even if non-null pre-import.
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
			name                       = local.oci_key_name_update
			schedule_for_deletion_days = 10
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
			cckm_key_id                = ciphertrust_oci_byok_key.aes.id
			source_key_id              = ciphertrust_cm_key.cm_key_version.id
			schedule_for_deletion_days = 10
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
			name                       = local.oci_key_name
			schedule_for_deletion_days = 8
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
			cckm_key_id                = ciphertrust_oci_byok_key.aes.id
			source_key_id              = ciphertrust_cm_key.cm_key_version.id
			schedule_for_deletion_days = 8
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
	// resetResourceStr resets schedule_for_deletion_days to 7 so keys are left with the
	// default deletion window after the non-default values tested in earlier steps.
	resetResourceStr := strings.NewReplacer("schedule_for_deletion_days = 8", "schedule_for_deletion_days = 7").Replace(minResourceStr)
	modifyKeyConfigStr := fmt.Sprintf(maxConfig, localsResource, connectionResource,
		`"tf-fake-source-key-id"`, "ciphertrust_oci_byok_key.aes.id")
	modifyVersionConfigStr := fmt.Sprintf(maxConfig, localsResource, connectionResource,
		"ciphertrust_cm_key.cm_aes_key.id", `"tf-fake-key-id"`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create step: no schedule_for_deletion_days in config; default of 7 is applied.
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
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					// version_summary reflects versions present at key-read time (not later-added versions in same apply)
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					// Version resource (byok_v1)
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "7"),
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
				// Update step: schedule_for_deletion_days = 10 for both key and version.
				Config: updateResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource -- scheduler switched to scheduler_2, name changed to oci_key_name_update
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "10"),
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "10"),
				),
			},
			{
				// Get the key deleted
				Config: connectionResource,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				// Min step: schedule_for_deletion_days = 8 for both key and version.
				Config: minResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource -- no rotation, no tags, default enable_key (true)
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "source_key_tier", "local"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "8"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "8"),
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
				ImportStateVerifyIgnore: []string{
					"schedule_for_deletion_days",
				},
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, versionResource),
			},
			{
				// Update step (second): no schedule_for_deletion_days; retained as 8 from prior state.
				Config: updateResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource -- schedule_for_deletion_days not in config; retained from prior state.
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "10"),
					// Version resource -- schedule_for_deletion_days = 10 (set explicitly in updateConfig).
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "10"),
				),
			},
			{
				// Create step (second): no schedule_for_deletion_days; retained as 10 (not reset to default 7).
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource -- schedule_for_deletion_days not in config; retained from prior state.
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "version_summary.0.version_id"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "10"),
					// Version resource -- schedule_for_deletion_days not in config; retained from prior state.
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "10"),
					// Key list data source
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					// Key version list data source
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "4"),
				),
			},
			{
				// Reset step: explicitly set schedule_for_deletion_days = 7 so any remaining
				// resources are left with the default 7-day deletion window before error-only steps.
				Config: resetResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "7"),
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

// TestCckmOCIByokKeyScheduledForDeletionRefresh verifies that when an OCI BYOK key is
// scheduled for deletion out-of-band (without Terraform), a subsequent terraform refresh
// retains the resource in state and issues a warning rather than removing it from state.
func TestCckmOCIByokKeyScheduledForDeletionRefresh(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	cmKeyName := "tf-" + uuid.New().String()[:8]
	ociKeyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_byok_key.key"

	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_key" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_oci_byok_key" "key" {
			name          = "%s"
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}`, cmKeyName, ociKeyName)

	var capturedKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a minimal OCI BYOK key; capture the CM ID for OOB deletion.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", keyResource)
						}
						capturedKeyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: schedule the key for deletion out-of-band, then refresh state.
				// Expected: provider issues a warning (not an error) and retains the resource
				// in state with lifecycle_state = "SCHEDULING_DELETION". OCI automatically
				// disables keys scheduled for deletion, so Terraform will report drift on
				// enable_key - ExpectNonEmptyPlan: true captures this expected drift.
				PreConfig: func() {
					scheduleOciKeyDeletionOutOfBand(capturedKeyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", keyResource)
						}
						if rs.Primary.ID != capturedKeyID {
							return fmt.Errorf("expected id %q, got %q", capturedKeyID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
		},
	})
}

// TestCckmOCIByokKeyScheduledForDeletionUpdate verifies that when an OCI BYOK key is
// scheduled for deletion out-of-band, a subsequent terraform apply that includes a name
// update produces a "Provider produced inconsistent result" error. OCI auto-disables the
// key when scheduling deletion, causing the actual state (enable_key=false) to differ from
// the plan (enable_key=true from the schema default), which the Terraform framework
// detects as an inconsistent result. The resource remains in state after this failure.
func TestCckmOCIByokKeyScheduledForDeletionUpdate(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	cmKeyName := "tf-" + uuid.New().String()[:8]
	ociKeyName := "tf-" + uuid.New().String()[:8]
	ociKeyNameUpdated := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_byok_key.key"

	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_key" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_oci_byok_key" "key" {
			name          = "%s"
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}`, cmKeyName, ociKeyName)

	updateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_key" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_oci_byok_key" "key" {
			name          = "%s"
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}`, cmKeyName, ociKeyNameUpdated)

	var capturedKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a minimal OCI BYOK key; capture the CM ID for OOB deletion.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", keyResource)
						}
						capturedKeyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: schedule the key for deletion out-of-band, then apply a name update.
				// Expected: OCI auto-disables the key when scheduling deletion, causing the
				// actual enable_key state (false) to differ from the plan (true from the schema
				// default). The Terraform framework raises an inconsistent result error.
				PreConfig: func() {
					scheduleOciKeyDeletionOutOfBand(capturedKeyID)
				},
				Config:      updateConfig,
				ExpectError: regexp.MustCompile("Provider produced inconsistent result"),
			},
		},
	})
}

// TestCckmOCIByokKeyVersionScheduledForDeletionRefresh verifies that when an OCI BYOK key
// version is scheduled for deletion out-of-band, a subsequent terraform refresh retains
// the resource in state and issues a warning rather than removing it from state.
// Two BYOK versions are created so that v1 is non-current and eligible for deletion scheduling.
func TestCckmOCIByokKeyVersionScheduledForDeletionRefresh(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	cmKeyName1 := "tf-" + uuid.New().String()[:8]
	cmKeyName2 := "tf-" + uuid.New().String()[:8]
	ociKeyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_byok_key.key"
	v1Resource := "ciphertrust_oci_byok_key_version.v1"
	v2Resource := "ciphertrust_oci_byok_key_version.v2"

	// Create BYOK key + v1 + v2. v2 depends_on v1 so v1 is created first.
	// After both are created, v2 is the current version and v1 is non-current.
	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_key_1" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_cm_key" "cm_key_2" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_oci_byok_key" "key" {
			name          = "%s"
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_key_1.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_byok_key_version" "v1" {
			cckm_key_id   = ciphertrust_oci_byok_key.key.id
			source_key_id = ciphertrust_cm_key.cm_key_1.id
		}
		resource "ciphertrust_oci_byok_key_version" "v2" {
			depends_on    = [ciphertrust_oci_byok_key_version.v1]
			cckm_key_id   = ciphertrust_oci_byok_key.key.id
			source_key_id = ciphertrust_cm_key.cm_key_2.id
		}`, cmKeyName1, cmKeyName2, ociKeyName)

	var capturedKeyID, capturedV1ID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create BYOK key + two versions; capture parent key CM ID and v1 CM ID.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
					resource.TestCheckResourceAttrSet(v2Resource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						capturedV1ID = rs.Primary.ID
						capturedKeyID = rs.Primary.Attributes["cckm_key_id"]
						return nil
					},
				),
			},
			{
				// Step 2: schedule v1 for deletion out-of-band, then refresh state.
				// Expected: v1 is retained in state with lifecycle_state = "SCHEDULING_DELETION".
				// v2 remains ENABLED.
				PreConfig: func() {
					scheduleOciKeyVersionDeletionOutOfBand(capturedKeyID, capturedV1ID)
				},
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						if rs.Primary.ID != capturedV1ID {
							return fmt.Errorf("expected v1 id %q, got %q", capturedV1ID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(v1Resource, "oci_key_version_params.lifecycle_state", "SCHEDULING_DELETION"),
					resource.TestCheckResourceAttr(v2Resource, "oci_key_version_params.lifecycle_state", "ENABLED"),
				),
			},
		},
	})
}

// TestCckmOCIByokKeyVersionScheduledForDeletionUpdate verifies that when an OCI BYOK key
// version is scheduled for deletion out-of-band, a subsequent terraform apply that changes
// schedule_for_deletion_days issues a warning, retains the resource in state, and does not error.
func TestCckmOCIByokKeyVersionScheduledForDeletionUpdate(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	cmKeyName1 := "tf-" + uuid.New().String()[:8]
	cmKeyName2 := "tf-" + uuid.New().String()[:8]
	ociKeyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_byok_key.key"
	v1Resource := "ciphertrust_oci_byok_key_version.v1"

	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_key_1" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_cm_key" "cm_key_2" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_oci_byok_key" "key" {
			name          = "%s"
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_key_1.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_byok_key_version" "v1" {
			cckm_key_id   = ciphertrust_oci_byok_key.key.id
			source_key_id = ciphertrust_cm_key.cm_key_1.id
		}
		resource "ciphertrust_oci_byok_key_version" "v2" {
			depends_on    = [ciphertrust_oci_byok_key_version.v1]
			cckm_key_id   = ciphertrust_oci_byok_key.key.id
			source_key_id = ciphertrust_cm_key.cm_key_2.id
		}`, cmKeyName1, cmKeyName2, ociKeyName)

	updateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_key_1" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_cm_key" "cm_key_2" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_oci_byok_key" "key" {
			name          = "%s"
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_key_1.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_byok_key_version" "v1" {
			cckm_key_id                = ciphertrust_oci_byok_key.key.id
			source_key_id              = ciphertrust_cm_key.cm_key_1.id
			schedule_for_deletion_days = 10
		}
		resource "ciphertrust_oci_byok_key_version" "v2" {
			depends_on    = [ciphertrust_oci_byok_key_version.v1]
			cckm_key_id   = ciphertrust_oci_byok_key.key.id
			source_key_id = ciphertrust_cm_key.cm_key_2.id
		}`, cmKeyName1, cmKeyName2, ociKeyName)

	var capturedKeyID, capturedV1ID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create BYOK key + two versions; capture parent key CM ID and v1 CM ID.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						capturedV1ID = rs.Primary.ID
						capturedKeyID = rs.Primary.Attributes["cckm_key_id"]
						return nil
					},
				),
			},
			{
				// Step 2: schedule v1 for deletion out-of-band, then apply a schedule_for_deletion_days update.
				// Expected: Update detects SCHEDULING_DELETION, issues a warning (not an error),
				// and retains v1 in state.
				PreConfig: func() {
					scheduleOciKeyVersionDeletionOutOfBand(capturedKeyID, capturedV1ID)
				},
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						if rs.Primary.ID != capturedV1ID {
							return fmt.Errorf("expected v1 id %q, got %q", capturedV1ID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(v1Resource, "oci_key_version_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
		},
	})
}
