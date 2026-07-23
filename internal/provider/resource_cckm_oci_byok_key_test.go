package provider

import (
	"fmt"
	"os"
	"regexp"
	"strings"
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

// TestCckmOCIByokKey is a comprehensive lifecycle test for ciphertrust_oci_byok_key and
// related version resources:
//
//   - Steps 1-2: ModifyPlan create-time rejections: enable_key=false and enable_auto_rotation
//     are both rejected with a plan-time error when set at resource creation.
//   - Steps 3-7: full-feature create (with defined/freeform tags) + refresh + import + update
//     (rotation, name change, sfd=10) using the first key; key is then destroyed.
//   - Steps 8-13: minimal create + refresh + import + update cycle on a second key.
//   - Steps 14-15: ModifyPlan immutability rejections: source_key_id and cckm_key_id are
//     rejected at plan time when changed on an existing resource.
//   - Steps 16-22: OOB version/key deletion scenarios (RefreshState retains with warning;
//     Update on a SCHEDULING_DELETION key triggers "Provider produced inconsistent result").
func TestCckmOCIByokKey(t *testing.T) {

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

	// minConfigV1Sfd10: same as minConfig with byok_v1.schedule_for_deletion_days = 10.
	// Used in the OOB version deletion update step.
	minConfigV1Sfd10 := `
		%s
		%s

		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
		}

		resource "ciphertrust_oci_byok_key" "aes" {
			name                       = local.oci_key_name
			schedule_for_deletion_days = 7
			oci_key_params = {
				protection_mode = "SOFTWARE"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id                = ciphertrust_oci_byok_key.aes.id
			source_key_id              = ciphertrust_cm_key.cm_key_version.id
			schedule_for_deletion_days = 10
		}

		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id   = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		resource "ciphertrust_oci_key_version" "native_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}`

	// minConfigKeyNameUpdate: same as minConfig with key name changed to
	// local.oci_key_name_update to trigger Update on the key (used in OOB key deletion test).
	minConfigKeyNameUpdate := `
		%s
		%s

		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
		}

		resource "ciphertrust_oci_byok_key" "aes" {
			name                       = local.oci_key_name_update
			schedule_for_deletion_days = 7
			oci_key_params = {
				protection_mode = "SOFTWARE"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id                = ciphertrust_oci_byok_key.aes.id
			source_key_id              = ciphertrust_cm_key.cm_key_version.id
			schedule_for_deletion_days = 10
		}

		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id   = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		resource "ciphertrust_oci_key_version" "native_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}`

	// disableAtCreateConfig: enable_key = false at create - rejected by ModifyPlan.
	disableAtCreateConfig := `
		%s
		%s

		resource "ciphertrust_cm_key" "cm_aes_key" {
			name       = local.cm_key_name
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}

		resource "ciphertrust_oci_byok_key" "aes" {
			enable_key    = false
			name          = local.oci_key_name
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id = ciphertrust_cm_key.cm_aes_key.id
			vault         = ciphertrust_oci_vault.vault.id
		}`

	// schedulerAtCreateConfig: enable_auto_rotation at create - rejected by ModifyPlan.
	schedulerAtCreateConfig := `
		%s
		%s

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
			source_key_id = ciphertrust_cm_key.cm_aes_key.id
			vault         = ciphertrust_oci_vault.vault.id
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
	// resetResourceStr: sets schedule_for_deletion_days = 7 (default) on key and byok_v1.
	resetResourceStr := strings.NewReplacer("schedule_for_deletion_days = 8", "schedule_for_deletion_days = 7").Replace(minResourceStr)
	// modifyKeyConfigStr: source_key_id changed to a fake value - triggers plan-time immutability error.
	modifyKeyConfigStr := fmt.Sprintf(maxConfig, localsResource, connectionResource,
		`"tf-fake-source-key-id"`, "ciphertrust_oci_byok_key.aes.id")
	// modifyVersionConfigStr: cckm_key_id on byok_v1 changed to a fake value - triggers plan-time error.
	modifyVersionConfigStr := fmt.Sprintf(maxConfig, localsResource, connectionResource,
		"ciphertrust_cm_key.cm_aes_key.id", `"tf-fake-key-id"`)
	// versionOobUpdateResourceStr: resetResourceStr equivalent with byok_v1.sfd = 10.
	versionOobUpdateResourceStr := fmt.Sprintf(minConfigV1Sfd10, localsResource, connectionResource)
	// keyOobUpdateResourceStr: renames the key to oci_key_name_update to trigger Update on
	// a SCHEDULING_DELETION key (final OOB step expects "Provider produced inconsistent result").
	keyOobUpdateResourceStr := fmt.Sprintf(minConfigKeyNameUpdate, localsResource, connectionResource)
	// disableAtCreateStr: enable_key = false at create - plan-time rejection test.
	disableAtCreateStr := fmt.Sprintf(disableAtCreateConfig, localsResource, connectionResource)
	// schedulerAtCreateStr: enable_auto_rotation at create - plan-time rejection test.
	schedulerAtCreateStr := fmt.Sprintf(schedulerAtCreateConfig, localsResource, connectionResource)

	var capturedByokKeyID, capturedByokV1ID string

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
			{
				// Step 3: create a valid key + versions; verify attributes and data sources.
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
				// Step 4: refresh state after create.
				RefreshState: true,
			},
			{
				// Step 5: import the key resource.
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreOCIKey,
			},
			{
				// Step 6: import the key version resource.
				ResourceName:      versionResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, versionResource),
			},
			{
				// Step 7: update - schedule_for_deletion_days = 10 for both key and version.
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
				// Step 8: destroy the first key so the min-config cycle creates a fresh key.
				Config: connectionResource,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				// Step 9: min create - schedule_for_deletion_days = 8 for both key and version.
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
				// Step 10: refresh state after min create.
				RefreshState: true,
			},
			{
				// Step 11: import the key resource.
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreOCIKey,
			},
			{
				// Step 12: import the key version resource.
				ResourceName:      versionResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"schedule_for_deletion_days",
				},
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, versionResource),
			},
			{
				// Step 13: update (second) - no schedule_for_deletion_days; retained as 8 from prior state.
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
				// Step 14: create (second) - no schedule_for_deletion_days; retained as 10 (not reset to default 7).
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
				// Step 15: reset - set schedule_for_deletion_days = 7 (default) on key and byok_v1.
				Config: resetResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "7"),
				),
			},
			{
				// Step 16: ModifyPlan - source_key_id changed, expect plan-time immutability error.
				Config:      modifyKeyConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
			{
				// Step 17: ModifyPlan - cckm_key_id changed on byok_v1, expect plan-time immutability error.
				Config:      modifyVersionConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
			{
				// Step 18: re-apply resetResourceStr to restore the correct config context
				// after the PlanOnly error steps (16, 17) used different configs.
				// Re-capture IDs here so step 19 OOB calls use the current resource IDs.
				Config: resetResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "7"),
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
				// Step 19: OOB version deletion - RefreshState: schedule byok_v1 for deletion out-of-band,
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
				// Step 20: OOB version deletion - Update: apply schedule_for_deletion_days = 10 on byok_v1.
				// byok_v1 is already SCHEDULING_DELETION. Expected: warning issued, byok_v1 retained.
				Config: versionOobUpdateResourceStr,
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
				// Step 21: OOB key deletion - RefreshState: schedule the key itself for deletion out-of-band.
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
				// Step 22: OOB key deletion - Update: apply a name change on the SCHEDULING_DELETION key.
				// OCI auto-disables the key, so enable_key in the post-apply read-back is false,
				// but the plan used the schema default (true). The Terraform framework raises
				// "Provider produced inconsistent result".
				Config:      keyOobUpdateResourceStr,
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
