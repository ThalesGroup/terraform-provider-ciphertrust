package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var _ = regexp.MustCompile

// initCckmOCITest builds the Terraform resource configuration used as a shared setup by most CCKM OCI
// tests. It creates an OCI connection and registers an OCI vault, exposing them as Terraform resources
// that each test can embed in its own config. Skips the test if the required OCI environment variables
// are not set.
func initCckmOCITest(t *testing.T) string {
	keyFile := os.Getenv("CCKM_OCI_KEY_FILE")
	pubKeyFP := os.Getenv("CCKM_OCI_FINGERPRINT")
	region := os.Getenv("CCKM_OCI_REGION")
	tenancyOCID := os.Getenv("CCKM_OCI_CONN_TENANCY")
	userOCID := os.Getenv("CCKM_OCI_USER")
	vaultOCID := os.Getenv("CCKM_OCI_VAULT")

	ok := keyFile != "" && pubKeyFP != "" && region != "" && tenancyOCID != "" && userOCID != "" /*&& compartmentOCID != "" */ && vaultOCID != ""
	if !ok {
		t.Skip("Failed to get OCI connection environment variables")
	}
	name := "tf-" + uuid.New().String()[:8]
	config := `
		locals {
			vault_ocid          = "%s"
			region              = "%s"
			cm_key_usage_mask   = %d
		}
		resource "ciphertrust_oci_connection" "oci_connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}
		resource "ciphertrust_oci_vault" "vault" {
			connection_id = ciphertrust_oci_connection.oci_connection.id
			vault_id      = local.vault_ocid
			region        = local.region
		}`
	resourceStr := fmt.Sprintf(config,
		vaultOCID, region, cmKeyUsageCryptoOps, keyFile, name, pubKeyFP, region, tenancyOCID, userOCID)
	return resourceStr
}

// scheduleOciKeyDeletionOutOfBand calls the OCI key schedule-deletion API directly,
// bypassing Terraform. Used in tests that verify provider behaviour when a key enters
// SCHEDULING_DELETION state without Terraform's knowledge.
// Failures are intentionally ignored - the test will catch any unexpected state.
func scheduleOciKeyDeletionOutOfBand(keyID string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	payload, _ := json.Marshal(map[string]int{"days": 7})
	_, _ = client.PostDataV2(
		context.Background(),
		"oob-schedule-oci-key-deletion-"+keyID,
		common.URL_OCI+"/keys/"+keyID+"/schedule-deletion",
		payload,
	)
}

// scheduleOciKeyVersionDeletionOutOfBand calls the OCI key version schedule-deletion API
// directly, bypassing Terraform.
// Failures are intentionally ignored - the test will catch any unexpected state.
func scheduleOciKeyVersionDeletionOutOfBand(keyID, versionID string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	payload, _ := json.Marshal(map[string]int{"days": 7})
	_, _ = client.PostDataV2(
		context.Background(),
		"oob-schedule-oci-version-deletion-"+versionID,
		common.URL_OCI+"/keys/"+keyID+"/versions/"+versionID+"/schedule-deletion",
		payload,
	)
}

// TestCckmOCIKeyNative is a comprehensive lifecycle test for ciphertrust_oci_key and
// ciphertrust_oci_key_version that runs all non-backup scenarios on a single OCI key:
//
//   - ModifyPlan create-time rejections: enable_key=false and enable_auto_rotation are
//     both rejected with a plan-time error when set at resource creation.
//   - Create with schedule_for_deletion_days, data source checks, import, and refresh.
//   - Update lifecycle: disable/re-enable, freeform tags, rename, scheduler add/change/remove.
//   - Post-update immutability checks: algorithm, length, and vault on the key; cckm_key_id
//     on the version. All produce a plan-time error and leave resources untouched.
//   - OOB version deletion: RefreshState retains version as SCHEDULING_DELETION; Update
//     (schedule_for_deletion_days) retains with warning.
//   - OOB key deletion: RefreshState retains key as SCHEDULING_DELETION (drift reported);
//     Update triggers "Provider produced inconsistent result".
func TestCckmOCIKeyNative(t *testing.T) {
	connectionResource := initCckmOCITest(t)

	keyName := "tf-" + uuid.New().String()[:8]
	keyNameUpdated := "tf-" + uuid.New().String()[:8]
	schedulerAtCreateName := "tf-" + uuid.New().String()[:8]
	schedulerOneName := "tf-" + uuid.New().String()[:8]
	schedulerTwoName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"
	v1Resource := "ciphertrust_oci_key_version.v1"
	v2Resource := "ciphertrust_oci_key_version.v2"
	keysDataSource := "data.ciphertrust_oci_key_list.keys"
	versionsDataSource := "data.ciphertrust_oci_key_version_list.versions"

	// disableAtCreateConfig: enable_key = false at create - rejected by ModifyPlan.
	disableAtCreateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			enable_key = false
			name       = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyName)

	// schedulerAtCreateConfig: enable_auto_rotation at create - rejected by ModifyPlan.
	schedulerAtCreateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params = {
				cloud_name = "oci"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_oci_key" "key" {
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler.id
				key_source    = "ciphertrust"
			}
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, schedulerAtCreateName, keyName)

	// createConfig: key + v1 + key-list data source + key-version-list data source.
	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name                       = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			schedule_for_deletion_days = 7
			vault                      = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id                = ciphertrust_oci_key.key.id
			schedule_for_deletion_days = 7
		}
		data "ciphertrust_oci_key_list" "keys" {
			depends_on = [ciphertrust_oci_key_version.v1]
			filters = {
				key_name = ciphertrust_oci_key.key.name
			}
		}
		data "ciphertrust_oci_key_version_list" "versions" {
			key_id     = ciphertrust_oci_key.key.id
			depends_on = [ciphertrust_oci_key_version.v1]
		}`, keyName)

	// The immutability configs use keyNameUpdated so no spurious name-update appears
	// in the plan alongside the immutability error. They are all used with PlanOnly:true.

	// badAlgorithmConfig: tries to change algorithm after creation - immutable.
	badAlgorithmConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "AES"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyNameUpdated)

	// badLengthConfig: tries to change length after creation - immutable.
	badLengthConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 512
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyNameUpdated)

	// badVaultConfig: tries to change vault after creation - immutable.
	badVaultConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = "tf-fake-vault-id"
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyNameUpdated)

	// badCckmKeyIdConfig: tries to change cckm_key_id on the version - immutable.
	badCckmKeyIdConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = "tf-fake-key-id"
		}`, keyNameUpdated)

	// updateConfig: disable key + rename + add freeform tag + keep v1 + data sources.
	updateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			enable_key = false
			name       = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				freeform_tags   = { env = "test" }
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}
		data "ciphertrust_oci_key_list" "keys" {
			depends_on = [ciphertrust_oci_key_version.v1]
			filters = {
				key_name = ciphertrust_oci_key.key.name
			}
		}
		data "ciphertrust_oci_key_version_list" "versions" {
			key_id     = ciphertrust_oci_key.key.id
			depends_on = [ciphertrust_oci_key_version.v1]
		}`, keyNameUpdated)

	// restoreConfig: re-enable key + clear freeform tag + keep v1.
	restoreConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				freeform_tags   = {}
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyNameUpdated)

	// addRotationConfig: link scheduler_one via enable_auto_rotation.
	addRotationConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_scheduler" "scheduler_one" {
			cckm_key_rotation_params = {
				cloud_name = "oci"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_oci_key" "key" {
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_one.id
				key_source    = "ciphertrust"
			}
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, schedulerOneName, keyNameUpdated)

	// changeRotationConfig: switch auto-rotation to scheduler_two.
	changeRotationConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_scheduler" "scheduler_one" {
			cckm_key_rotation_params = {
				cloud_name = "oci"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_scheduler" "scheduler_two" {
			cckm_key_rotation_params = {
				cloud_name = "oci"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 10 * * sun"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_oci_key" "key" {
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_two.id
				key_source    = "ciphertrust"
			}
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, schedulerOneName, schedulerTwoName, keyNameUpdated)

	// removeRotationConfig: omit enable_auto_rotation block. Both schedulers remain in
	// config and are destroyed in the following afterImmutabilityConfig step.
	removeRotationConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_scheduler" "scheduler_one" {
			cckm_key_rotation_params = {
				cloud_name = "oci"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_scheduler" "scheduler_two" {
			cckm_key_rotation_params = {
				cloud_name = "oci"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 10 * * sun"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, schedulerOneName, schedulerTwoName, keyNameUpdated)

	// afterImmutabilityConfig: applied after PlanOnly immutability steps to confirm key and
	// v1 are still ENABLED and immutable attributes are unchanged. Schedulers are omitted so
	// they are destroyed here as a side effect (normal cleanup).
	// Also used as a point to capture key and v1 IDs for the OOB deletion steps that follow.
	afterImmutabilityConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyNameUpdated)

	// twoVersionsConfig: key + v1 + v2. v2 depends_on v1, making v1 non-current.
	// Required before an OOB version deletion (only non-current versions are eligible).
	twoVersionsConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}
		resource "ciphertrust_oci_key_version" "v2" {
			depends_on  = [ciphertrust_oci_key_version.v1]
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyNameUpdated)

	// twoVersionsUpdateV1Config: same as twoVersionsConfig with v1.schedule_for_deletion_days = 7.
	twoVersionsUpdateV1Config := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id                = ciphertrust_oci_key.key.id
			schedule_for_deletion_days = 7
		}
		resource "ciphertrust_oci_key_version" "v2" {
			depends_on  = [ciphertrust_oci_key_version.v1]
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyNameUpdated)

	// oobKeyUpdateConfig: rename key back to keyName to trigger Update on a key that is
	// already in SCHEDULING_DELETION (step 21 expects "Provider produced inconsistent result").
	oobKeyUpdateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id                = ciphertrust_oci_key.key.id
			schedule_for_deletion_days = 7
		}
		resource "ciphertrust_oci_key_version" "v2" {
			depends_on  = [ciphertrust_oci_key_version.v1]
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyName)

	var capturedKeyID, capturedV1ID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: enable_key = false at create must be rejected at plan time.
				Config:      disableAtCreateConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid create-time attribute`),
			},
			{
				// Step 2: enable_auto_rotation at create must be rejected at plan time.
				Config:      schedulerAtCreateConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid create-time attribute`),
			},
			{
				// Step 3: create a valid key + v1; verify attributes and data sources.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.length", "256"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "oci_key_params.key_id"),
					resource.TestCheckResourceAttrSet(keyResource, "vault_id"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					// Version resource
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
					resource.TestCheckResourceAttrPair(v1Resource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(v1Resource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(v1Resource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(v1Resource, "oci_key_version_params.version_id"),
					resource.TestCheckResourceAttr(v1Resource, "schedule_for_deletion_days", "7"),
					// Key list data source
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					resource.TestCheckResourceAttr(keysDataSource, "matched", "1"),
					resource.TestCheckResourceAttrPair(keysDataSource, "keys.0.id", keyResource, "id"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.0.oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.0.oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.0.oci_key_params.length", "256"),
					// Key version list data source
					resource.TestCheckResourceAttr(versionsDataSource, "versions.#", "2"),
					resource.TestCheckResourceAttr(versionsDataSource, "matched", "2"),
					resource.TestCheckResourceAttrSet(versionsDataSource, "versions.0.id"),
				),
			},
			{
				// Step 4: refresh state - verify no unexpected drift.
				RefreshState: true,
			},
			{
				// Step 5: import the key resource and verify all computed attributes round-trip.
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreOCIKey,
			},
			{
				// Step 6: import the key version resource.
				ResourceName:      v1Resource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"schedule_for_deletion_days",
				},
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, v1Resource),
			},
			{
				// Step 7: disable key + rename + add freeform tag.
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "DISABLED"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.env", "test"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
				),
			},
			{
				// Step 8: re-enable key + clear freeform tag (name stays keyNameUpdated).
				Config: restoreConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.%", "0"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
				),
			},
			{
				// Step 9: add scheduler_one and enable auto-rotation.
				Config: addRotationConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
				),
			},
			{
				// Step 10: switch auto-rotation to scheduler_two.
				Config: changeRotationConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
				),
			},
			{
				// Step 11: remove enable_auto_rotation block - auto_rotate must become false.
				Config: removeRotationConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
				),
			},
			{
				// Step 12: changing algorithm must be rejected at plan time.
				// State is unchanged (PlanOnly) - key must NOT be destroyed.
				Config:      badAlgorithmConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// Step 13: changing length must be rejected at plan time.
				Config:      badLengthConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// Step 14: changing vault must be rejected at plan time.
				Config:      badVaultConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// Step 15: changing cckm_key_id on the version must be rejected at plan time.
				Config:      badCckmKeyIdConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// Step 16: re-apply a clean config to confirm key and version are still ENABLED
				// with all immutable attributes unchanged. Schedulers are destroyed here as a
				// side effect since they are not present in this config.
				// Capture key and v1 IDs for the OOB deletion tests that follow.
				Config: afterImmutabilityConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.length", "256"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found: %s", keyResource)
						}
						capturedKeyID = rs.Primary.ID
						return nil
					},
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found: %s", v1Resource)
						}
						capturedV1ID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 17: add v2 (depends_on v1) so that v1 becomes non-current.
				// Only non-current versions are eligible for OOB scheduled deletion.
				Config: twoVersionsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
					resource.TestCheckResourceAttrSet(v2Resource, "id"),
				),
			},
			{
				// Step 18: schedule v1 for deletion OOB, then refresh state.
				// Expected: v1 retained with lifecycle_state = SCHEDULING_DELETION;
				// v2 remains ENABLED.
				PreConfig: func() {
					scheduleOciKeyVersionDeletionOutOfBand(capturedKeyID, capturedV1ID)
				},
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found: %s", v1Resource)
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
			{
				// Step 19: apply update with schedule_for_deletion_days = 7 on v1.
				// v1 is already SCHEDULING_DELETION. Expected: provider issues a warning
				// (not an error) and retains v1 in state with SCHEDULING_DELETION.
				Config: twoVersionsUpdateV1Config,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found: %s", v1Resource)
						}
						if rs.Primary.ID != capturedV1ID {
							return fmt.Errorf("expected v1 id %q, got %q", capturedV1ID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(v1Resource, "oci_key_version_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
			{
				// Step 20: schedule the key itself for deletion OOB, then refresh state.
				// OCI auto-disables keys when scheduling deletion, causing drift on enable_key
				// (plan wants true from schema default, read-back is false).
				// Expected: key retained with lifecycle_state = SCHEDULING_DELETION.
				PreConfig: func() {
					scheduleOciKeyDeletionOutOfBand(capturedKeyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found: %s", keyResource)
						}
						if rs.Primary.ID != capturedKeyID {
							return fmt.Errorf("expected key id %q, got %q", capturedKeyID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
			{
				// Step 21: apply a rename on the SCHEDULING_DELETION key.
				// OCI auto-disables the key, so enable_key in the post-apply read-back is false,
				// but the plan used the schema default (true). The Terraform framework raises
				// "Provider produced inconsistent result".
				Config:      oobKeyUpdateConfig,
				ExpectError: regexp.MustCompile("Provider produced inconsistent result"),
			},
		},
	})
}

// TestCckmOCIKeyRestoreFromBackup verifies that setting restore_from_backup_trigger on a
// native OCI key triggers a restore from the most recent OCI backup.
// Applicable only to HSM-protected keys in OCI Virtual Private Vaults.
// Skipped if CCKM_OCI_VP_VAULT_OCID is not set.
func TestCckmOCIKeyRestoreFromBackup(t *testing.T) {
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

	keyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"
	versionResource := "ciphertrust_oci_key_version.version"

	createConfig := fmt.Sprintf(`
			resource "ciphertrust_oci_key" "key" {
				name = "%s"
				oci_key_params = {
					algorithm       = "AES"
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					length          = 32
					protection_mode = "HSM"
				}
				vault = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_key_version" "version" {
				cckm_key_id = ciphertrust_oci_key.key.id
			}`, keyName)

	restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_oci_key" "key" {
				name = "%s"
				oci_key_params = {
					algorithm       = "AES"
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					length          = 32
					protection_mode = "HSM"
				}
				restore_from_backup_trigger = "1"
				vault = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_key_version" "version" {
				cckm_key_id = ciphertrust_oci_key.key.id
			}`, keyName)

	var capturedVersionUpdatedAt string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create an HSM-protected native key and a version on the VP vault.
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

// TestCckmOCIByokKeyRestoreFromBackup has been moved to resource_cckm_oci_byok_key_test.go.
func _TestCckmOCIByokKeyRestoreFromBackup_moved(t *testing.T) {
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
