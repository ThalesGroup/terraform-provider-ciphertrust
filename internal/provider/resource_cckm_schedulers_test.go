package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmSchedulersRotation(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		createSchedulerParams := `
			resource "ciphertrust_scheduler" "rotation_max_params" {
			  cckm_key_rotation_params {
				cloud_name = "aws"
				expiration = "%s"
				expire_in = "%s"
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
		createConfig := fmt.Sprintf(createSchedulerParams, expiration, expireIn, maxParamsName, minParamsName)
		expirationUpdate := "55d"
		expireInUpdate := "33h"
		updateConfig := fmt.Sprintf(updateSchedulerParams, expirationUpdate, expireInUpdate, maxParamsName, expirationUpdate, expireInUpdate, minParamsName)
		resource.Test(t, resource.TestCase{
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

						resource.TestCheckResourceAttrSet(minParamsResource, "id"),
						resource.TestCheckResourceAttrSet(minParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						testCheckAttributeNotSet(minParamsResource, "cckm_key_rotation_params.0.expiration"),
						testCheckAttributeNotSet(minParamsResource, "cckm_key_rotation_params.0.expire_in"),
					),
				},
				{
					Config: updateConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(maxParamsResource, "id"),
						resource.TestCheckResourceAttrSet(maxParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expiration", expirationUpdate),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expire_in", expireInUpdate),

						resource.TestCheckResourceAttrSet(minParamsResource, "id"),
						resource.TestCheckResourceAttrSet(minParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.expiration", expirationUpdate),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.expire_in", expireInUpdate),
					),
				},
				{
					Config: createConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(maxParamsResource, "id"),
						resource.TestCheckResourceAttrSet(maxParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expiration", expiration),
						resource.TestCheckResourceAttr(maxParamsResource, "cckm_key_rotation_params.0.expire_in", expireIn),

						resource.TestCheckResourceAttrSet(minParamsResource, "id"),
						resource.TestCheckResourceAttrSet(minParamsResource, "cckm_key_rotation_params.#"),
						resource.TestCheckResourceAttr(minParamsResource, "cckm_key_rotation_params.0.cloud_name", "aws"),
						testCheckAttributeNotSet(minParamsResource, "cckm_key_rotation_params.0.expiration"),
						testCheckAttributeNotSet(minParamsResource, "cckm_key_rotation_params.0.expire_in"),
					),
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
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: schedulerConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(schedulerResourceName, "id"),
						resource.TestCheckResourceAttr(schedulerResourceName, "cckm_xks_credential_rotation_params.cloud_name", "aws"),
					),
				},
			},
		})
	})

	t.Run("oci", func(t *testing.T) {
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
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfigStr,
				},
			},
		})
	})
}

func TestCckmSchedulersSync(t *testing.T) {
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
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfigStr,
				},
			},
		})
	})
}
