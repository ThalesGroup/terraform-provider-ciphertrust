package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmSchedulersRotationDataSource(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		createSchedulerParams := `
			resource "ciphertrust_scheduler" "aws_scheduled_rotation_job" {
				cckm_key_rotation_params = {
					cloud_name = "aws"
					expiration = "%s"
					expire_in = "%s"
					rotation_after = "6d"
					rotate_material = true
					aws_retain_alias = true
				}
				name       = "%s"
				operation  = "cckm_key_rotation"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "aws_scheduled_rotation_job_2" {
				cckm_key_rotation_params = {
					cloud_name = "aws"
				}
				name      = "%s"
				operation = "cckm_key_rotation"
				run_at    = "0 9 * * fri"
			}
			data "ciphertrust_scheduler_list" "aws_scheduled_rotation_job" {
				filters = {
					id = ciphertrust_scheduler.aws_scheduled_rotation_job.id
				}

			}
			data "ciphertrust_scheduler_list" "aws_no_filter" {
				depends_on = [
					ciphertrust_scheduler.aws_scheduled_rotation_job,
					ciphertrust_scheduler.aws_scheduled_rotation_job_2,
				]
			}`
		resourceName := "ciphertrust_scheduler.aws_scheduled_rotation_job"
		datasourceName := "data.ciphertrust_scheduler_list.aws_scheduled_rotation_job"
		noFilterDatasourceName := "data.ciphertrust_scheduler_list.aws_no_filter"
		schedulerName := "aws-key-rotation-" + uuid.New().String()[:8]
		schedulerName2 := "aws-key-rotation-" + uuid.New().String()[:8]
		expiration := "44d"
		expireIn := "22h"
		rotateMaterialExpectedValue := "true"
		createConfig := fmt.Sprintf(createSchedulerParams, expiration, expireIn, schedulerName, schedulerName2)
		if getCipherTrustVersion() < 221 {
			rotateMaterialExpectedValue = "false"
			createConfig = strings.ReplaceAll(createConfig, "rotate_material = true", "")
		}
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAwsKMS() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(resourceName, "id"),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.cloud_name", "aws"),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.expiration", expiration),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.rotation_after", "6d"),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.rotate_material", rotateMaterialExpectedValue),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.aws_retain_alias", "true"),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.expire_in", expireIn),

						resource.TestCheckResourceAttr(datasourceName, "scheduler.#", "1"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.operation", "cckm_key_rotation"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.cloud_name", "aws"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.expiration", expiration),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.rotation_after", "6d"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.expire_in", expireIn),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.aws_params.rotate_material", rotateMaterialExpectedValue),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.aws_params.retain_alias", "true"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.run_at", "0 9 * * fri"),

						// No-filter datasource: verify at least both created schedulers are returned
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.0.id"),
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.1.id"),
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
			}
			resource "ciphertrust_scheduler" "xks_credential_rotation_2" {
				cckm_xks_credential_rotation_params = {
					cloud_name = "aws"
				}
				name      = "%s"
				operation = "cckm_xks_credential_rotation"
				run_at    = "0 9 * * fri"
			}
			data "ciphertrust_scheduler_list" "xks_credential_rotation" {
				filters = {
					id = ciphertrust_scheduler.xks_credential_rotation.id
				}
			}
			data "ciphertrust_scheduler_list" "xks_no_filter" {
				depends_on = [
					ciphertrust_scheduler.xks_credential_rotation,
					ciphertrust_scheduler.xks_credential_rotation_2,
				]
			}`
		schedulerName := "tf-xks-cred-rotation" + uuid.New().String()[:8]
		schedulerName2 := "tf-xks-cred-rotation" + uuid.New().String()[:8]
		schedulerConfigStr := fmt.Sprintf(schedulerConfig, schedulerName, schedulerName2)
		resourceName := "ciphertrust_scheduler.xks_credential_rotation"
		datasourceName := "data.ciphertrust_scheduler_list.xks_credential_rotation"
		noFilterDatasourceName := "data.ciphertrust_scheduler_list.xks_no_filter"
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAwsKMS() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: schedulerConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(resourceName, "id"),
						resource.TestCheckResourceAttr(resourceName, "cckm_xks_credential_rotation_params.cloud_name", "aws"),

						resource.TestCheckResourceAttr(datasourceName, "scheduler.#", "1"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_xks_credential_rotation_params.cloud_name", "aws"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.operation", "cckm_xks_credential_rotation"),

						// No-filter datasource: verify at least both created schedulers are returned
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.0.id"),
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.1.id"),
					),
				},
			},
		})
	})

	t.Run("oci", func(t *testing.T) {
		createConfig := `
			resource "ciphertrust_scheduler" "oci_rotation_scheduler" {
				cckm_key_rotation_params = {
					cloud_name = "oci"
					expiration = "%s"
					expire_in  = "%s"
				}
				name       = "%s"
				operation  = "cckm_key_rotation"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "oci_rotation_scheduler_2" {
				cckm_key_rotation_params = {
					cloud_name = "oci"
				}
				name      = "%s"
				operation = "cckm_key_rotation"
				run_at    = "0 9 * * fri"
			}
			data "ciphertrust_scheduler_list" "oci_rotation_scheduler" {
				filters = {
					id = ciphertrust_scheduler.oci_rotation_scheduler.id
				}
			}
			data "ciphertrust_scheduler_list" "oci_no_filter" {
				depends_on = [
					ciphertrust_scheduler.oci_rotation_scheduler,
					ciphertrust_scheduler.oci_rotation_scheduler_2,
				]
			}`
		expiration := "44d"
		expireIn := "22h"
		name := "tf" + uuid.New().String()[:8]
		name2 := "tf" + uuid.New().String()[:8]
		resourceName := "ciphertrust_scheduler.oci_rotation_scheduler"
		datasourceName := "data.ciphertrust_scheduler_list.oci_rotation_scheduler"
		noFilterDatasourceName := "data.ciphertrust_scheduler_list.oci_no_filter"
		createConfigStr := fmt.Sprintf(createConfig, expiration, expireIn, name, name2)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmOCIVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.cloud_name", "oci"),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.expiration", expiration),
						resource.TestCheckResourceAttr(resourceName, "cckm_key_rotation_params.expire_in", expireIn),

						resource.TestCheckResourceAttr(datasourceName, "scheduler.#", "1"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.operation", "cckm_key_rotation"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.cloud_name", "oci"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.expiration", expiration),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_key_rotation_params.expire_in", expireIn),

						// No-filter datasource: verify at least both created schedulers are returned
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.0.id"),
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.1.id"),
					),
				},
			},
		})
	})
}

func TestCckmSchedulersSyncDataSource(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		connectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		createParams := `
			resource "ciphertrust_scheduler" "aws_sync_job" {
				cckm_synchronization_params = {
					cloud_name  = "aws"
					kms         = [ciphertrust_aws_kms.kms.id]
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "aws_sync_job_2" {
				cckm_synchronization_params = {
					cloud_name      = "aws"
					synchronize_all = true
				}
				name      = "%s"
				operation = "cckm_synchronization"
				run_at    = "0 9 * * fri"
			}
			data "ciphertrust_scheduler_list" "aws_sync_job" {
				filters = {
					id = ciphertrust_scheduler.aws_sync_job.id
				}
			}
			data "ciphertrust_scheduler_list" "aws_sync_no_filter" {
				depends_on = [
					ciphertrust_scheduler.aws_sync_job,
					ciphertrust_scheduler.aws_sync_job_2,
				]
			}`
		resourceName := "ciphertrust_scheduler.aws_sync_job"
		datasourceName := "data.ciphertrust_scheduler_list.aws_sync_job"
		noFilterDatasourceName := "data.ciphertrust_scheduler_list.aws_sync_no_filter"
		syncJobName := "tf" + uuid.New().String()[:8]
		syncJobName2 := "tf" + uuid.New().String()[:8]
		createConfig := connectionResource + fmt.Sprintf(createParams, syncJobName, syncJobName2)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAwsKMS() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(resourceName, "id"),
						resource.TestCheckResourceAttr(resourceName, "cckm_synchronization_params.kms.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "cckm_synchronization_params.cloud_name", "aws"),
						resource.TestCheckResourceAttr(resourceName, "cckm_synchronization_params.synchronize_all", "false"),

						resource.TestCheckResourceAttr(datasourceName, "scheduler.#", "1"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.operation", "cckm_synchronization"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_synchronization_params.cloud_name", "aws"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_synchronization_params.synchronize_all", "false"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_synchronization_params.kms.#", "1"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.run_at", "0 9 * * fri"),

						// No-filter datasource: verify at least both created schedulers are returned
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.0.id"),
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.1.id"),
					),
				},
			},
		})
	})
	t.Run("oci", func(t *testing.T) {
		connectionResource := initCckmOCITest(t)
		createConfig := `
			resource "ciphertrust_scheduler" "oci_sync_job" {
				cckm_synchronization_params = {
					cloud_name  = "oci"
					oci_vaults  = [ciphertrust_oci_vault.vault.id]
				}
				name       = "%s"
				operation  = "cckm_synchronization"
				run_at     = "0 9 * * fri"
			}
			resource "ciphertrust_scheduler" "oci_sync_job_2" {
				cckm_synchronization_params = {
					cloud_name      = "oci"
					synchronize_all = true
				}
				name      = "%s"
				operation = "cckm_synchronization"
				run_at    = "0 9 * * fri"
			}
			data "ciphertrust_scheduler_list" "oci_sync_job" {
				filters = {
					id = ciphertrust_scheduler.oci_sync_job.id
				}
			}
			data "ciphertrust_scheduler_list" "oci_sync_no_filter" {
				depends_on = [
					ciphertrust_scheduler.oci_sync_job,
					ciphertrust_scheduler.oci_sync_job_2,
				]
			}`
		resourceName := "ciphertrust_scheduler.oci_sync_job"
		datasourceName := "data.ciphertrust_scheduler_list.oci_sync_job"
		noFilterDatasourceName := "data.ciphertrust_scheduler_list.oci_sync_no_filter"
		syncJobName := "tf" + uuid.New().String()[:8]
		syncJobName2 := "tf" + uuid.New().String()[:8]
		createConfigStr := connectionResource + fmt.Sprintf(createConfig, syncJobName, syncJobName2)
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmOCIVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(resourceName, "id"),
						resource.TestCheckResourceAttr(resourceName, "cckm_synchronization_params.oci_vaults.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "cckm_synchronization_params.cloud_name", "oci"),
						resource.TestCheckResourceAttr(resourceName, "cckm_synchronization_params.synchronize_all", "false"),

						resource.TestCheckResourceAttr(datasourceName, "scheduler.#", "1"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.operation", "cckm_synchronization"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_synchronization_params.cloud_name", "oci"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_synchronization_params.synchronize_all", "false"),
						resource.TestCheckResourceAttr(datasourceName, "scheduler.0.cckm_synchronization_params.oci_vaults.#", "1"),

						// No-filter datasource: verify at least both created schedulers are returned
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.0.id"),
						resource.TestCheckResourceAttrSet(noFilterDatasourceName, "scheduler.1.id"),
					),
				},
			},
		})
	})
}

// TestCckmSchedulersListAllDataSource creates one scheduler of each CCKM
// operation type and verifies that a datasource filtered by "operation=cckm*"
// returns at least three results.
func TestCckmSchedulersListAllDataSource(t *testing.T) {
	config := `
		resource "ciphertrust_scheduler" "rotation" {
			cckm_key_rotation_params = {
				cloud_name = "aws"
			}
			name      = "%s"
			operation = "cckm_key_rotation"
			run_at    = "0 9 * * fri"
		}
		resource "ciphertrust_scheduler" "sync" {
			cckm_synchronization_params = {
				cloud_name      = "aws"
				synchronize_all = true
			}
			name      = "%s"
			operation = "cckm_synchronization"
			run_at    = "0 9 * * fri"
		}
		resource "ciphertrust_scheduler" "xks" {
			cckm_xks_credential_rotation_params = {
				cloud_name = "aws"
			}
			name      = "%s"
			operation = "cckm_xks_credential_rotation"
			run_at    = "0 9 * * fri"
		}
		data "ciphertrust_scheduler_list" "all_cckm" {
			filters = {
				operation = "cckm*"
			}
			depends_on = [
				ciphertrust_scheduler.rotation,
				ciphertrust_scheduler.sync,
				ciphertrust_scheduler.xks,
			]
		}`

	rotationName := "tf-rot-" + uuid.New().String()[:8]
	syncName := "tf-sync-" + uuid.New().String()[:8]
	xksName := "tf-xks-" + uuid.New().String()[:8]
	dsName := "data.ciphertrust_scheduler_list.all_cckm"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(config, rotationName, syncName, xksName),
				Check: resource.ComposeTestCheckFunc(
					// Verify at least three results are returned.
					resource.TestCheckResourceAttrSet(dsName, "scheduler.0.id"),
					resource.TestCheckResourceAttrSet(dsName, "scheduler.1.id"),
					resource.TestCheckResourceAttrSet(dsName, "scheduler.2.id"),
					// Verify each of our created schedulers appears in the list.
					testCheckListContainsName(dsName, "scheduler", "name", rotationName),
					testCheckListContainsName(dsName, "scheduler", "name", syncName),
					testCheckListContainsName(dsName, "scheduler", "name", xksName),
				),
			},
		},
	})
}
