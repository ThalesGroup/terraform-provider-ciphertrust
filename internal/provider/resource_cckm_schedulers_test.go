package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// blockImportIgnore lists the block attributes that are stored as empty lists
// when not configured, but arrive as null after import+Read. ImportStateVerify
// treats [] != null as a mismatch, so we ignore the unused block for each
// operation type.
var (
	rotationImportIgnore = []string{"cckm_synchronization_params"}
	syncImportIgnore     = []string{"cckm_key_rotation_params"}
	xksCredImportIgnore  = []string{"cckm_key_rotation_params", "cckm_synchronization_params"}
)

func TestCckmSchedulersRotationResource(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		createSchedulerParams := `
			resource "ciphertrust_scheduler" "rotation_max_params" {
				cckm_key_rotation_params {
					cloud_name = "aws"
					expiration = "%s"
					expire_in = "%s"
					rotation_after = "%s"
					rotate_material = true
				}
				name       = "%s"
				operation  = "cckm_key_rotation"
				run_at     = "0 9 * * fri"
				}
			resource "ciphertrust_scheduler" "rotation_min_params" {
				cckm_key_rotation_params {
					cloud_name = "aws"
				}
				name       = "%s"
				operation  = "cckm_key_rotation"
				run_at     = "0 9 * * fri"
			}`
		updateSchedulerParams := `
			resource "ciphertrust_scheduler" "rotation_max_params" {
				cckm_key_rotation_params {
					cloud_name = "aws"
					expiration = "%s"
					expire_in = "%s"
					rotation_after = "%s"
					rotate_material = false
				}
				name       = "%s"
				operation  = "cckm_key_rotation"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "rotation_min_params" {
				cckm_key_rotation_params {
					cloud_name = "aws"
					expiration = "%s"
					expire_in = "%s"
					rotation_after = "%s"
					rotate_material = true
				}
				name       = "%s"
				operation  = "cckm_key_rotation"
				run_at     = "0 9 * * fri"
			}`
		updateSchedulerParams2 := `
		resource "ciphertrust_scheduler" "rotation_max_params" {
			cckm_key_rotation_params {
				cloud_name = "aws"
				expiration = ""
				expire_in = ""
				rotation_after = ""
				rotate_material = false
			}
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * fri"
		}
		resource "ciphertrust_scheduler" "rotation_min_params" {
			cckm_key_rotation_params {
				cloud_name = "aws"
				expiration = ""
				expire_in = ""
				rotation_after = ""
				rotate_material = false
			}
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * fri"
		}`
		maxParamsResource := "ciphertrust_scheduler.rotation_max_params"
		minParamsResource := "ciphertrust_scheduler.rotation_min_params"
		maxParamsName := "MaxParams" + uuid.New().String()[:8]
		minParamsName := "MinParams" + uuid.New().String()[:8]
		expiration := "44d"
		expireIn := "22h"
		rotationAfter := "6d"
		createConfig := fmt.Sprintf(createSchedulerParams, expiration, expireIn,
			rotationAfter, maxParamsName, minParamsName)
		expirationUpdate := "55d"
		expireInUpdate := "33h"
		rotationAfterUpdate := "8d"
		updateConfig := fmt.Sprintf(updateSchedulerParams, expirationUpdate, expireInUpdate,
			rotationAfterUpdate, maxParamsName, expirationUpdate, expireInUpdate,
			rotationAfterUpdate, minParamsName)
		updateConfig2 := fmt.Sprintf(updateSchedulerParams2, maxParamsName, minParamsName)
		rotateMaterialExpectedTrueValue := "true"
		if getCipherTrustVersion() < 221 {
			rotateMaterialExpectedTrueValue = "false"
			createConfig = strings.ReplaceAll(createConfig, "rotate_material = true", "")
			updateConfig = strings.ReplaceAll(updateConfig, "rotate_material = true", "")
			updateConfig2 = strings.ReplaceAll(updateConfig2, "rotate_material = true", "")
		}
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAwsKMS() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(maxParamsResource, "id"),
						resource.TestCheckResourceAttrSet(maxParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expiration", expiration),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expire_in", expireIn),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.rotation_after", rotationAfter),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.rotate_material", rotateMaterialExpectedTrueValue),

						resource.TestCheckResourceAttrSet(minParamsResource, "id"),
						resource.TestCheckResourceAttrSet(minParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
					),
				},
				{
					RefreshState: true,
				},
				// Import the fully-configured scheduler and verify all rotation params round-trip.
				{
					ResourceName:            maxParamsResource,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: rotationImportIgnore,
				},
				// Import the minimal scheduler (cloud_name only) to verify sparse round-trip.
				{
					ResourceName:            minParamsResource,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: rotationImportIgnore,
				},
				{
					Config: updateConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(maxParamsResource, "id"),
						resource.TestCheckResourceAttrSet(maxParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expiration", expirationUpdate),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expire_in", expireInUpdate),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.rotation_after", rotationAfterUpdate),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.rotate_material", "false"),

						resource.TestCheckResourceAttrSet(minParamsResource, "id"),
						resource.TestCheckResourceAttrSet(minParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.expiration", expirationUpdate),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.expire_in", expireInUpdate),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.rotation_after", rotationAfterUpdate),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.rotate_material", rotateMaterialExpectedTrueValue),
					),
				},
				{
					RefreshState: true,
				},
				{
					Config: updateConfig2,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(maxParamsResource, "id"),
						resource.TestCheckResourceAttrSet(maxParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expiration", ""),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expire_in", ""),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.rotation_after", ""),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.rotate_material", "false"),

						resource.TestCheckResourceAttrSet(minParamsResource, "id"),
						resource.TestCheckResourceAttrSet(minParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.expiration", ""),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.expire_in", ""),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.rotation_after", ""),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.rotate_material", "false"),
					),
				},
				{
					RefreshState: true,
				},
			},
		})
	})

	t.Run("XKSCredentialRotation", func(t *testing.T) {
		schedulerConfig := `
			resource "ciphertrust_scheduler" "xks_credential_rotation" {
				cckm_xks_credential_rotation_params = {
					cloud_name = "aws"
				}
				name       = "%s"
				operation  = "cckm_xks_credential_rotation"
				run_at     = "0 9 * * fri"
			}`
		schedulerName := "tf-xks-cred-rotation" + uuid.New().String()[:8]
		schedulerConfigStr := fmt.Sprintf(schedulerConfig, schedulerName)
		schedulerResourceName := "ciphertrust_scheduler.xks_credential_rotation"
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAwsKMS() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: schedulerConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(schedulerResourceName, "id"),
						resource.TestCheckResourceAttr(schedulerResourceName, "cckm_xks_credential_rotation_params.cloud_name", "aws"),
					),
				},
				{
					RefreshState: true,
				},
				{
					ResourceName:            schedulerResourceName,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: xksCredImportIgnore,
				},
			},
		})
	})

	t.Run("oci", func(t *testing.T) {
		schedulerResource := "ciphertrust_scheduler.oci"
		createConfig := `
			resource "ciphertrust_scheduler" "oci" {
				cckm_key_rotation_params {
					cloud_name = "oci"
					expiration = "%s"
					expire_in  = "%s"
				}
				name       = "%s"
				operation  = "cckm_key_rotation"
				run_at     = "0 9 * * fri"
			}`
		expiration := "44d"
		expireIn := "22h"
		name := "tf" + uuid.New().String()[:8]
		createConfigStr := fmt.Sprintf(createConfig, expiration, expireIn, name)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmOCIVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(schedulerResource, "id"),
						resource.TestCheckResourceAttr(schedulerResource, "cckm_key_rotation_params.0.cloud_name", "oci"),
						resource.TestCheckResourceAttr(schedulerResource, "cckm_key_rotation_params.0.expiration", expiration),
						resource.TestCheckResourceAttr(schedulerResource, "cckm_key_rotation_params.0.expire_in", expireIn),
					),
				},
				{
					RefreshState: true,
				},
				{
					ResourceName:            schedulerResource,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: rotationImportIgnore,
				},
			},
		})
	})
}

func TestCckmSchedulersSyncResource(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		connectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		createParams := `
			resource "ciphertrust_scheduler" "sync_kms_params" {
				cckm_synchronization_params {
					cloud_name  = "aws"
					kms         = [ciphertrust_aws_kms.kms.id]
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "sync_all_params" {
				cckm_synchronization_params {
					cloud_name      = "aws"
					synchronize_all = true
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}`
		updateParams := `
			resource "ciphertrust_scheduler" "sync_kms_params" {
				cckm_synchronization_params {
					cloud_name      = "aws"
					synchronize_all = true
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "sync_all_params" {
				cckm_synchronization_params {
					cloud_name = "aws"
	               kms        = [ciphertrust_aws_kms.kms.id]
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}`
		kmsParamsResource := "ciphertrust_scheduler.sync_kms_params"
		syncAllParamsResource := "ciphertrust_scheduler.sync_all_params"
		kmsParamsName := "KmsParams" + uuid.New().String()[:8]
		syncAllParamsName := "SyncAllParams" + uuid.New().String()[:8]
		createConfig := connectionResource + fmt.Sprintf(createParams, kmsParamsName, syncAllParamsName)
		updateConfig := connectionResource + fmt.Sprintf(updateParams, kmsParamsName, syncAllParamsName)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAwsKMS() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(kmsParamsResource, "id"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.kms.#", "1"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.synchronize_all", "false"),

						resource.TestCheckResourceAttrSet(syncAllParamsResource, "id"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.kms.#", "0"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.synchronize_all", "true"),
					),
				},
				// Import the KMS-scoped scheduler and verify kms list and synchronize_all round-trip.
				{
					ResourceName:            kmsParamsResource,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: syncImportIgnore,
				},
				// Import the synchronize_all scheduler and verify round-trip.
				{
					ResourceName:            syncAllParamsResource,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: syncImportIgnore,
				},
				{
					Config: updateConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(kmsParamsResource, "id"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.kms.#", "0"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.synchronize_all", "true"),

						resource.TestCheckResourceAttrSet(syncAllParamsResource, "id"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.kms.#", "1"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.synchronize_all", "false"),
					),
				},
				{
					Config: createConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(kmsParamsResource, "id"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.kms.#", "1"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(kmsParamsResource, "cckm_synchronization_params.0.synchronize_all", "false"),

						resource.TestCheckResourceAttrSet(syncAllParamsResource, "id"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.kms.#", "0"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(syncAllParamsResource, "cckm_synchronization_params.0.synchronize_all", "true"),
					),
				},
			},
		})
	})
	t.Run("oci", func(t *testing.T) {
		connectionResource := initCckmOCITest(t)
		syncVaultResource := "ciphertrust_scheduler.sync_vault"
		syncAllResource := "ciphertrust_scheduler.sync_all"
		createConfig := `
			resource "ciphertrust_scheduler" "sync_vault" {
				cckm_synchronization_params {
					cloud_name  = "oci"
					oci_vaults  = [ciphertrust_oci_vault.vault.id]
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "sync_all" {
				cckm_synchronization_params {
					cloud_name      = "oci"
					synchronize_all = true
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}`
		syncVaultName := "oci-sync-vault" + uuid.New().String()[:8]
		syncAllName := "oci-sync-all" + uuid.New().String()[:8]
		createConfigStr := connectionResource + fmt.Sprintf(createConfig, syncVaultName, syncAllName)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmOCIVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(syncVaultResource, "id"),
						resource.TestCheckResourceAttr(syncVaultResource, "cckm_synchronization_params.0.cloud_name", "oci"),
						resource.TestCheckResourceAttr(syncVaultResource, "cckm_synchronization_params.0.oci_vaults.#", "1"),
						resource.TestCheckResourceAttr(syncVaultResource, "cckm_synchronization_params.0.synchronize_all", "false"),

						resource.TestCheckResourceAttrSet(syncAllResource, "id"),
						resource.TestCheckResourceAttr(syncAllResource, "cckm_synchronization_params.0.cloud_name", "oci"),
						resource.TestCheckResourceAttr(syncAllResource, "cckm_synchronization_params.0.oci_vaults.#", "0"),
						resource.TestCheckResourceAttr(syncAllResource, "cckm_synchronization_params.0.synchronize_all", "true"),
					),
				},
				{
					RefreshState: true,
				},
				// Import vault-scoped scheduler and verify oci_vaults and synchronize_all round-trip.
				{
					ResourceName:            syncVaultResource,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: syncImportIgnore,
				},
				// Import synchronize_all scheduler and verify round-trip.
				{
					ResourceName:            syncAllResource,
					ImportState:             true,
					ImportStateVerify:       true,
					ImportStateVerifyIgnore: syncImportIgnore,
				},
			},
		})
	})
}
