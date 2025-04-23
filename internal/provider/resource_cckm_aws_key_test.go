package provider

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	guuid "github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const (
	awsKeyNamePrefix    = "tf-aws-"
	cckmKeyNamePrefix   = "tf-cm-"
	awsLocalPrefix      = "tf-aws-local-"
	awsPolicyUserPrefix = "arn:aws:iam::556782317223:user/"
	awsPolicyRolePrefix = "arn:aws:iam::556782317223:role/"
)

var (
	awsKeyUsers  = []string{"cdua-terraform-user", "rpandita"}
	awsKeyRoles  = []string{"cckm-role-with-ext-id", "DATAENG_ROLE"}
	awsKeyPolicy = `{
	"Id": "key-consolepolicy-3",
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "Enable IAM UserName Permissions",
		"Effect": "Allow",
		"Principal": {
			"AWS": "arn:aws:iam::556782317223:root"
		},
		"Action": "kms:*",
		"Resource": "*"
	}]
}`
)

func initCckmAwsTest() (string, bool) {
	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if awsAccessKeyID == "" || awsSecretAccessKey == "" {
		return "", false
	}
	awsConfig := `
		provider "ciphertrust" {}
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "TerraformTest"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection  = ciphertrust_aws_connection.aws_connection.id
			name           = "TerraformTest"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[0],
				data.ciphertrust_aws_account_details.account_details.regions[1],
				data.ciphertrust_aws_account_details.account_details.regions[2],
				"us-west-1",
			]
		}
		locals {
			alias   = "%s"
		}`
	awsConnectionResource := fmt.Sprintf(awsConfig, "TF-Test-"+guuid.New().String())
	return awsConnectionResource, true
}

func testCheckAttributeNotSet(resourceName string, attributeName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for rn, rs := range s.RootModule().Resources {
			if rn != resourceName {
				continue
			}
			if rs.Primary.ID == "" {
				return fmt.Errorf("error: %s resource ID is not set", resourceName)
			}
			keys := make([]string, 0, len(rs.Primary.Attributes))
			for k := range rs.Primary.Attributes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if k == attributeName {
					return fmt.Errorf("error: found %s:%s is set to %s but it should not be set", resourceName, attributeName, rs.Primary.Attributes[k])
				}
			}
			return nil
		}
		return fmt.Errorf("error: did not find resource %s so can't list attributes", resourceName)
	}
}

func testAccVerifyResourceDeleted(resourceType string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for _, rs := range s.RootModule().Resources {
			if rs.Type == resourceType {
				return fmt.Errorf("error: resource %s still exists", resourceType)
			}
		}
		return nil
	}
}

func testAwsVerifySceduleridAndJobConfig(schedulerResourceName string, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Get scheduler resource ID
		schRes, ok := s.RootModule().Resources[schedulerResourceName]
		if !ok {
			return fmt.Errorf("scheduler resource not found")
		}
		schID := schRes.Primary.ID
		fmt.Println("Scheduler ID:", schID)

		// Get ciphertrus_aws_key.labels.job_config
		awsKey, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("aws key resource not found")
		}
		jbConfig := awsKey.Primary.Attributes["labels.job_config_id"]
		fmt.Println("labels.job_config_id:", jbConfig)

		if schID != jbConfig {
			return fmt.Errorf("mismatch: ciphertrust_scheduler.scheduled_rotation_job.id = %s, ciphertrust_aws_key.aws_key.labels.job_config_id = %s", schID, jbConfig)
		}
		return nil
	}
}

func TestCckmAwsKeyDetailed(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createKeyWithExtrasConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias        = [local.alias, "%s", "%s"]
			customer_master_key_spec = "RSA_4096"
			description  = "CreateKeyWithExtras original description"
			enable_key   = false
			key_policy {
				key_admins  = ["%s"]
				key_users   = ["%s"]
				key_admins_roles  = ["%s"]
				key_users_roles   = ["%s"]
			}
			key_usage    = "SIGN_VERIFY"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey1 = "CreateKeyWithExtras_TagValue1"
				TagKey2 = "CreateKeyWithExtras_TagValue2"
			}
		}`
	updateKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias        = [local.alias]
			customer_master_key_spec = "RSA_4096"
			description  = "CreateKeyWithExtras new description"
			enable_key   = true
			key_policy {
				policy = <<-EOT
					%s
				EOT
			}
			key_usage = "SIGN_VERIFY"
			kms       = ciphertrust_aws_kms.kms.id
			region    = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey3 = "CreateKeyWithExtras_TagValue3"
				TagKey1 = "CreateKeyWithExtras_TagValue1"
				TagKey2 = "CreateKeyWithExtras_TagValue2"
			}
		}`
	var aliasList []string
	aliasList = append(aliasList, awsKeyNamePrefix+guuid.New().String())
	aliasList = append(aliasList, awsKeyNamePrefix+guuid.New().String())
	resourceName := "ciphertrust_aws_key.aws_key"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyWithExtrasConfig, aliasList[0], aliasList[1],
					awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "3"),
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "customer_master_key_spec", "RSA_4096"),
					resource.TestCheckResourceAttr(resourceName, "description", "CreateKeyWithExtras original description"),
					resource.TestCheckResourceAttr(resourceName, "enable_key", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "key_id"),
					resource.TestCheckResourceAttr(resourceName, "key_usage", "SIGN_VERIFY"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "CreateKeyWithExtras_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "CreateKeyWithExtras_TagValue2"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(updateKeyConfig, awsKeyPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "description", "CreateKeyWithExtras new description"),
					resource.TestCheckResourceAttr(resourceName, "enable_key", "true"),
					resource.TestCheckResourceAttr(resourceName, "key_users.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_admin.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_admin_roles.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "CreateKeyWithExtras_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "CreateKeyWithExtras_TagValue2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey3", "CreateKeyWithExtras_TagValue3"),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyWithExtrasConfig, aliasList[0], aliasList[1],
					awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "3"),
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "customer_master_key_spec", "RSA_4096"),
					resource.TestCheckResourceAttr(resourceName, "description", "CreateKeyWithExtras original description"),
					resource.TestCheckResourceAttr(resourceName, "enable_key", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "key_id"),
					resource.TestCheckResourceAttr(resourceName, "key_usage", "SIGN_VERIFY"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "CreateKeyWithExtras_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "CreateKeyWithExtras_TagValue2"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
		},
	})
}

func TestCckmAwsSchedulers(t *testing.T) {
	t.Run("Rotation", func(t *testing.T) {
		connectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		createParams := `
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
			}
			resource "ciphertrust_aws_key" "aws_key" {
				kms        = ciphertrust_aws_kms.kms.id
				region     = ciphertrust_aws_kms.kms.regions[0]
				enable_rotation {
					disable_encrypt = true
					job_config_id   = ciphertrust_scheduler.rotation_max_params.id
					key_source      = "ciphertrust"	
				}
			}`
		updateParams := `
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
			}
			resource "ciphertrust_aws_key" "aws_key" {
				kms        = ciphertrust_aws_kms.kms.id
				region     = ciphertrust_aws_kms.kms.regions[0]
				enable_rotation {
					disable_encrypt = false
					job_config_id   = ciphertrust_scheduler.rotation_min_params.id
					key_source      = "ciphertrust"
				}
			}`
		awsKeyResource := "ciphertrust_aws_key.aws_key"
		maxParamsResource := "ciphertrust_scheduler.rotation_max_params"
		minParamsResource := "ciphertrust_scheduler.rotation_min_params"
		maxParamsName := "MaxParams" + guuid.New().String()[:8]
		minParamsName := "MinParams" + guuid.New().String()[:8]
		expiration := "44d"
		expireIn := "22h"
		createConfig := connectionResource + fmt.Sprintf(createParams, expiration, expireIn, maxParamsName, minParamsName)
		expirationUpdate := "55d"
		expireInUpdate := "33h"
		updateConfig := connectionResource + fmt.Sprintf(updateParams, expirationUpdate, expireInUpdate, maxParamsName, expirationUpdate, expireInUpdate, minParamsName)
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

						resource.TestCheckResourceAttrSet(awsKeyResource, "id"),
						resource.TestCheckResourceAttrPair(awsKeyResource, "enable_rotation.0.job_config_id", maxParamsResource, "id"),
						resource.TestCheckResourceAttr(awsKeyResource, "enable_rotation.0.disable_encrypt", "true"),
						resource.TestCheckResourceAttr(awsKeyResource, "enable_rotation.0.key_source", "ciphertrust"),
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

						resource.TestCheckResourceAttrSet(awsKeyResource, "id"),
						resource.TestCheckResourceAttrPair(awsKeyResource, "enable_rotation.0.job_config_id", minParamsResource, "id"),
						resource.TestCheckResourceAttr(awsKeyResource, "enable_rotation.0.disable_encrypt", "false"),
						resource.TestCheckResourceAttr(awsKeyResource, "enable_rotation.0.key_source", "ciphertrust"),
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

						resource.TestCheckResourceAttrSet(awsKeyResource, "id"),
						resource.TestCheckResourceAttrPair(awsKeyResource, "enable_rotation.0.job_config_id", maxParamsResource, "id"),
						resource.TestCheckResourceAttr(awsKeyResource, "enable_rotation.0.disable_encrypt", "true"),
						resource.TestCheckResourceAttr(awsKeyResource, "enable_rotation.0.key_source", "ciphertrust"),
					),
				},
			},
		})
	})
	t.Run("Synchronization", func(t *testing.T) {
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
		kmsParamsName := "KmsParams" + guuid.New().String()[:8]
		syncAllParamsName := "SyncAllParams" + guuid.New().String()[:8]
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
}

func TestCckmAwsImportLocalKey(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	importLocalKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key_min" {
			import_key_material {
				source_key_name = "%s"
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_key" "aws_key_max" {
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration = %t
				valid_to = "%s"
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}`

	updateImportKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key_min" {
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration = %t
				valid_to = "%s"
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_key" "aws_key_max" {
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration = %t
				valid_to = "%s"
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}
	`

	localKeyNameMin := awsLocalPrefix + guuid.New().String()
	localKeyNameMax := awsLocalPrefix + guuid.New().String()
	utc, _ := time.LoadLocation("UTC")
	validTo := time.Now().In(utc).AddDate(0, 0, 1).Format(time.RFC3339)
	validToUpate := time.Now().In(utc).AddDate(0, 0, 2).Format(time.RFC3339)

	importLocalResourceMin := "ciphertrust_aws_key.aws_key_min"
	importLocalResourceMax := "ciphertrust_aws_key.aws_key_max"

	importConfig := awsConnectionResource + fmt.Sprintf(importLocalKeyConfig, localKeyNameMin, localKeyNameMax, false, validTo)
	updateImportConfig := awsConnectionResource + fmt.Sprintf(updateImportKeyConfig, localKeyNameMin, false, validTo, localKeyNameMax, false, validToUpate)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: importConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(importLocalResourceMin, "key_id"),
					// resource.TestCheckResourceAttr(importLocalResourceMin, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(importLocalResourceMax, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(importLocalResourceMax, "key_state", "Enabled"),

					resource.TestCheckResourceAttrSet(importLocalResourceMax, "key_id"),
					// resource.TestCheckResourceAttr(importLocalResourceMax, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(importLocalResourceMax, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(importLocalResourceMax, "key_state", "Enabled"),
				),
			},
			{
				Config: updateImportConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(importLocalResourceMin, "key_id"),
					// resource.TestCheckResourceAttr(importLocalResourceMin, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "key_state", "Enabled"),

					resource.TestCheckResourceAttrSet(importLocalResourceMax, "key_id"),
					// resource.TestCheckResourceAttr(importLocalResourceMax, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "key_state", "Enabled"),
				),
			},
			{
				Config: updateImportConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(importLocalResourceMin, "key_id"),
					// resource.TestCheckResourceAttr(importLocalResourceMin, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "key_state", "Enabled"),

					resource.TestCheckResourceAttrSet(importLocalResourceMax, "key_id"),
					// resource.TestCheckResourceAttr(importLocalResourceMax, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(importLocalResourceMin, "key_state", "Enabled"),
				),
			},
		},
	})
}

func TestCckmAwsMultiRegionKey(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	createKeyConfig := `
	resource "ciphertrust_aws_key" "aws_key" {
		alias                    = [local.alias, "%s"]
		customer_master_key_spec = "RSA_4096"
		key_usage                = "SIGN_VERIFY"
		kms                      = ciphertrust_aws_kms.kms.id
		region                   = ciphertrust_aws_kms.kms.regions[0]
		tags = {
			CreateTagKey1 = "CreateMultiRegionTagValue1"
			CreateTagKey2 = "CreateMultiRegionTagValue2"
		}
		multi_region = true
	}`

	replicateAboveKeyConfig := `
	resource "ciphertrust_aws_key" "aws_key" {
		alias                    = [local.alias, "%s", "%s"]
		customer_master_key_spec = "RSA_4096"
		key_usage                = "SIGN_VERIFY"
		kms                      = ciphertrust_aws_kms.kms.id
		region                   = ciphertrust_aws_kms.kms.regions[0]
		tags = {
			CreateTagKey1 = "CreateMultiRegionTagValue1"
			CreateTagKey2 = "CreateMultiRegionTagValue2"
		}
		multi_region = true
	}
	resource "ciphertrust_aws_key" "replicate_key"{
		region 					= ciphertrust_aws_kms.kms.regions[1]
		description 			= "replicate key description"
		origin					= "AWS_KMS"
		tags = {
			ReplicateKey = "ReplicateTagValue"
		}
		replicate_key {
			key_id 				= ciphertrust_aws_key.aws_key.key_id
		}
	}`

	replicateAgainKeyConfig := `
	resource "ciphertrust_aws_key" "aws_key" {
		alias                    = [local.alias, "%s", "%s"]
		customer_master_key_spec = "RSA_4096"
		key_usage                = "SIGN_VERIFY"
		kms                      = ciphertrust_aws_kms.kms.id
		region                   = ciphertrust_aws_kms.kms.regions[0]
		tags = {
			CreateTagKey1 = "CreateMultiRegionTagValue1"
			CreateTagKey2 = "CreateMultiRegionTagValue2"
		}
		multi_region = true
	}
	resource "ciphertrust_aws_key" "replicate_key"{
		region 					= ciphertrust_aws_kms.kms.regions[1]
		description 			= "replicate key description"
		origin					= "AWS_KMS"
		tags = {
			ReplicateKey = "ReplicateTagValue"
		}
		replicate_key {
			key_id 				= ciphertrust_aws_key.aws_key.key_id
		}
	}
	resource "ciphertrust_aws_key" "replicate_again_key" {
		region					= ciphertrust_aws_kms.kms.regions[2]
		description 			= "replicate key and make it primary"
		origin					= "AWS_KMS"
		replicate_key {
			key_id 				= ciphertrust_aws_key.aws_key.key_id
			make_primary 		= true
		}
	}`

	alias := awsLocalPrefix + guuid.New().String()
	updateAlias := awsLocalPrefix + guuid.New().String()
	createKeyResource := "ciphertrust_aws_key.aws_key"
	replicateKeyResource := "ciphertrust_aws_key.replicate_key"
	replicateKeyAgainResource := "ciphertrust_aws_key.replicate_again_key"

	createConfig := awsConnectionResource + fmt.Sprintf(createKeyConfig, alias)
	replicateKeyConfig := awsConnectionResource + fmt.Sprintf(replicateAboveKeyConfig, alias, updateAlias)
	replicateAgainConfig := awsConnectionResource + fmt.Sprintf(replicateAgainKeyConfig, alias, updateAlias)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(createKeyResource, "multi_region", "true"),
					resource.TestCheckResourceAttr(createKeyResource, "multi_region_replica_keys.#", "0"),
					resource.TestCheckResourceAttr(createKeyResource, "tags.CreateTagKey1", "CreateMultiRegionTagValue1"),
					resource.TestCheckResourceAttr(createKeyResource, "tags.CreateTagKey2", "CreateMultiRegionTagValue2"),
					resource.TestCheckResourceAttrSet(createKeyResource, "region"),
					resource.TestCheckResourceAttr(createKeyResource, "multi_region_key_type", "PRIMARY"),
				),
			},
			{
				Config: replicateKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(replicateKeyResource, "multi_region", "true"),
					resource.TestCheckResourceAttr(replicateKeyResource, "multi_region_replica_keys.#", "1"),
					resource.TestCheckResourceAttr(replicateKeyResource, "tags.ReplicateKey", "ReplicateTagValue"),
					resource.TestCheckResourceAttrSet(replicateKeyResource, "region"),
					resource.TestCheckResourceAttr(replicateKeyResource, "tags.%", "1"),
					resource.TestCheckResourceAttr(replicateKeyResource, "description", "replicate key description"),
					resource.TestCheckResourceAttr(replicateKeyResource, "multi_region_key_type", "REPLICA"),
				),
			},
			{
				Config: replicateAgainConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(replicateKeyAgainResource, "multi_region", "true"),
					resource.TestCheckResourceAttr(replicateKeyAgainResource, "multi_region_replica_keys.#", "2"),
					resource.TestCheckResourceAttrSet(replicateKeyAgainResource, "region"),
					// resource.TestCheckResourceAttr(replicateKeyAgainResource, "multi_region_key_type", "PRIMARY"),
				),
			},
		},
	})
}

func TestCckmAwsMultiRegionSymmAndAsymmKey(t *testing.T) {
	t.Run("Symmetric Key", func(t *testing.T) {
		awsConnectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		multiRegionSymmetricKeyResourceConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias        = [local.alias]
			customer_master_key_spec = "RSA_4096"
			description  = "MultiRegionReplicateAwsSymmetricKey create key description"
			key_policy {
			 key_admins  = ["%s"]
			 key_users   = ["%s"]
			 key_admins_roles  = ["%s"]
			 key_users_roles   = ["%s"]
			}
			key_usage    = "SIGN_VERIFY"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {
			  TagKey1 = "MultiRegionReplicateAwsSymmetricKey_TagValue1"
			  TagKey2 = "MultiRegionReplicateAwsSymmetricKey_TagValue2"
			}
			multi_region = true
		}

		resource "ciphertrust_aws_key" "replicated_key" {
		  alias = ["%s"]
		  bypass_policy_lockout_safety_check = true
		  description                        = "MultiRegionReplicateAwsSymmetricKey replicate key description"
		  key_policy {
			policy = <<-EOT
			  %s
		  EOT
		  }
		  region                             = ciphertrust_aws_kms.kms.regions[1]
		  replicate_key {
			key_id = ciphertrust_aws_key.aws_key.key_id
		  }
		  origin                             = "AWS_KMS"
		  tags = {
			TagKey = "MultiRegionReplicateAwsSymmetricKey_TagValue"
		  }
		  #primary_region                   = ciphertrust_aws_kms.kms.regions[1]
		}`

		replicaKeyAlias := awsKeyNamePrefix + guuid.New().String()
		updatePrimaryRegionKeyConfig := strings.Replace(multiRegionSymmetricKeyResourceConfig, "#primary_region", "primary_region", -1)
		createKeyResourceName := "ciphertrust_aws_key.aws_key"
		replicatedKeyResourceName := "ciphertrust_aws_key.replicated_key"
		createKeyConfig := awsConnectionResource + fmt.Sprintf(multiRegionSymmetricKeyResourceConfig, awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1], replicaKeyAlias, awsKeyPolicy)
		updatePrimaryRegionConfig := awsConnectionResource + fmt.Sprintf(updatePrimaryRegionKeyConfig, awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1], replicaKeyAlias, awsKeyPolicy)

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createKeyConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(createKeyResourceName, "alias.#", "1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "multi_region", "true"),
						resource.TestCheckResourceAttr(createKeyResourceName, "tags.%", "2"),
						resource.TestCheckResourceAttr(createKeyResourceName, "tags.TagKey1", "MultiRegionReplicateAwsSymmetricKey_TagValue1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "tags.TagKey2", "MultiRegionReplicateAwsSymmetricKey_TagValue2"),
						resource.TestCheckResourceAttr(createKeyResourceName, "description", "MultiRegionReplicateAwsSymmetricKey create key description"),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_admins.#", "1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_users.#", "1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_admins_roles.#", "1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_users_roles.#", "1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
						resource.TestCheckResourceAttr(createKeyResourceName, "multi_region_key_type", "PRIMARY"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "alias.0", replicaKeyAlias),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "multi_region", "true"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "tags.%", "1"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "tags.TagKey", "MultiRegionReplicateAwsSymmetricKey_TagValue"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "description", "MultiRegionReplicateAwsSymmetricKey replicate key description"),
						resource.TestCheckResourceAttrSet(replicatedKeyResourceName, "policy"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "multi_region_key_type", "REPLICA"),
					),
				},
				{
					Config: updatePrimaryRegionConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(createKeyResourceName, "alias.#", "1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "multi_region", "true"),
						resource.TestCheckResourceAttr(createKeyResourceName, "tags.%", "2"),
						resource.TestCheckResourceAttr(createKeyResourceName, "tags.TagKey1", "MultiRegionReplicateAwsSymmetricKey_TagValue1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "tags.TagKey2", "MultiRegionReplicateAwsSymmetricKey_TagValue2"),
						resource.TestCheckResourceAttr(createKeyResourceName, "description", "MultiRegionReplicateAwsSymmetricKey create key description"),
						resource.TestCheckResourceAttrSet(createKeyResourceName, "policy"),
						resource.TestCheckResourceAttr(createKeyResourceName, "multi_region_key_type", "PRIMARY"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "alias.0", replicaKeyAlias),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "multi_region", "true"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "tags.%", "1"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "tags.TagKey", "MultiRegionReplicateAwsSymmetricKey_TagValue"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "description", "MultiRegionReplicateAwsSymmetricKey replicate key description"),
						resource.TestCheckResourceAttrSet(replicatedKeyResourceName, "policy"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "multi_region_key_type", "PRIMARY"),
					),
				},
			},
		})
	})

	t.Run("Asymmetric Key", func(t *testing.T) {
		awsConnectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}

		replicateAsymmetricKey := `
		resource "ciphertrust_aws_key" "aws_key" {
		  alias                    = [local.alias]
		  customer_master_key_spec = "RSA_4096"
		  description              = "MultiRegionReplicateAwsAsymmetricKey create key"
		  kms                      = ciphertrust_aws_kms.kms.id
		  multi_region             = true
		  region                   = ciphertrust_aws_kms.kms.regions[0]
		}

		resource "ciphertrust_aws_key" "replicated_key" {
		  alias = [local.alias]
		  bypass_policy_lockout_safety_check = true
		  description              = "MultiRegionReplicateAwsAsymmetricKey replicated key"
		  origin                   = "AWS_KMS"
		  region                   = ciphertrust_aws_kms.kms.regions[1]
		  primary_region           = ciphertrust_aws_kms.kms.regions[1]
		  replicate_key {
			key_id = ciphertrust_aws_key.aws_key.key_id
		  }
		  tags = {
			TagKey = "MultiRegionReplicateAwsAsymmetricKey_TagValue"
		  }
		}`

		createKeyResourceName := "ciphertrust_aws_key.aws_key"
		replicatedKeyResourceName := "ciphertrust_aws_key.replicated_key"
		replicateAsymmetricKeyConfig := awsConnectionResource + fmt.Sprintf(replicateAsymmetricKey)
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: replicateAsymmetricKeyConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(createKeyResourceName, "alias.#", "1"),
						resource.TestCheckResourceAttr(createKeyResourceName, "description", "MultiRegionReplicateAwsAsymmetricKey create key"),
						resource.TestCheckResourceAttr(createKeyResourceName, "multi_region", "true"),
						resource.TestCheckResourceAttrSet(createKeyResourceName, "policy"),
						resource.TestCheckResourceAttr(createKeyResourceName, "multi_region_key_type", "PRIMARY"),

						resource.TestCheckResourceAttr(replicatedKeyResourceName, "alias.#", "1"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "description", "MultiRegionReplicateAwsAsymmetricKey replicated key"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "multi_region", "true"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "tags.%", "1"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "tags.TagKey", "MultiRegionReplicateAwsAsymmetricKey_TagValue"),
						resource.TestCheckResourceAttrSet(replicatedKeyResourceName, "policy"),
						resource.TestCheckResourceAttr(replicatedKeyResourceName, "multi_region_key_type", "REPLICA"),
					),
				},
			},
		})
	})
}

func TestCckmAwsMultiRegionImportKeyLocalMaterial(t *testing.T) {

	t.Run("Local Key Material", func(t *testing.T) {
		awsConnectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		importMultiRegionLocalKey := `
		resource "ciphertrust_aws_key" "aws_key_min" {
		  alias       = ["%s"]
		  description = "MultiRegionExternalKeyLocalMaterial create key"
		  import_key_material {
			source_key_name = "%s"
		  }
		  kms          = ciphertrust_aws_kms.kms.id
		  multi_region = true
		  region       = ciphertrust_aws_kms.kms.regions[0]
		}

		resource "ciphertrust_aws_key" "replicated_key_min" {
		  alias       = ["%s"]
		  description = "MultiRegionExternalKeyLocalMaterial replicated key"
		  region      = ciphertrust_aws_kms.kms.regions[1]
		  replicate_key {
			import_key_material = true
			key_id              = ciphertrust_aws_key.aws_key_min.key_id
		  }
		}
		resource "ciphertrust_aws_key" "aws_key_max" {
		  alias       = ["%s"]
		  description = "MultiRegionExternalKeyLocalMaterial create key"
		  import_key_material {
			key_expiration  = true
			source_key_name = "%s"
			source_key_tier = "local"
			valid_to        = "%s"
		  }
		  kms          = ciphertrust_aws_kms.kms.id
		  multi_region = true
		  region       = ciphertrust_aws_kms.kms.regions[0]
          key_policy {
            key_admins  = ["%s"]
             key_users   = ["%s"]
             key_admins_roles  = ["%s"]
             key_users_roles   = ["%s"]
          }
		}

		resource "ciphertrust_aws_key" "replicated_key_max" {
		  alias       = ["%s"]
		  description = "MultiRegionExternalKeyLocalMaterial replicated key"
		  region      = ciphertrust_aws_kms.kms.regions[1]
		  replicate_key {
			key_expiration      = true
			import_key_material = true
			key_id              = ciphertrust_aws_key.aws_key_max.key_id
			make_primary        = true
			valid_to            = "%s"
		  }
          key_policy {
            policy = <<-EOT
              %s
            EOT
          }
		}`

		aliasNameMin := "TF-Test-" + guuid.New().String()
		aliasNameMax := "TF-Test-" + guuid.New().String()
		localKeyNameMin := cckmKeyNamePrefix + guuid.New().String()
		localKeyNameMax := cckmKeyNamePrefix + guuid.New().String()
		utc, _ := time.LoadLocation("UTC")
		validTo := time.Now().In(utc).AddDate(0, 0, 1).Format(time.RFC3339)

		replicaKeyAliasMin := awsKeyNamePrefix + guuid.New().String()
		replicaKeyAliasMax := awsKeyNamePrefix + guuid.New().String()

		createMultiRegionLocalKeyMin := "ciphertrust_aws_key.aws_key_min"
		createMultiRegionLocalKeyMax := "ciphertrust_aws_key.aws_key_max"

		replicateMultiRegionLocalKeyMin := "ciphertrust_aws_key.replicated_key_min"
		replicateMultiRegionLocalKeyMax := "ciphertrust_aws_key.replicated_key_max"

		createConfig := awsConnectionResource + fmt.Sprintf(importMultiRegionLocalKey, aliasNameMin, localKeyNameMin, replicaKeyAliasMin, aliasNameMax,
			localKeyNameMax, validTo, awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1], replicaKeyAliasMax, validTo, awsKeyPolicy)

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfig,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMin, "alias.#", "1"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMin, "multi_region", "true"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMin, "description", "MultiRegionExternalKeyLocalMaterial create key"),
						resource.TestCheckResourceAttrSet(createMultiRegionLocalKeyMin, "key_id"),
						// resource.TestCheckResourceAttr(createMultiRegionLocalKeyMin, "key_material_origin", "cckm"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMin, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMin, "key_state", "Enabled"),

						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMin, "alias.0", replicaKeyAliasMin),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMin, "multi_region", "true"),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMin, "description", "MultiRegionExternalKeyLocalMaterial replicated key"),
						resource.TestCheckResourceAttrSet(replicateMultiRegionLocalKeyMin, "key_id"),
						// resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMin, "key_material_origin", "cckm"),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMin, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMin, "key_state", "Enabled"),

						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "alias.#", "1"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "multi_region", "true"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "description", "MultiRegionExternalKeyLocalMaterial create key"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_admins.#", "1"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_users.#", "1"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_admins_roles.#", "1"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_users_roles.#", "1"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
						resource.TestCheckResourceAttrSet(createMultiRegionLocalKeyMax, "policy"),
						resource.TestCheckResourceAttrSet(createMultiRegionLocalKeyMax, "key_id"),
						// resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_material_origin", "cckm"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(createMultiRegionLocalKeyMax, "key_state", "Enabled"),

						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMax, "alias.0", replicaKeyAliasMax),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMax, "multi_region", "true"),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMax, "description", "MultiRegionExternalKeyLocalMaterial replicated key"),
						resource.TestCheckResourceAttrSet(replicateMultiRegionLocalKeyMax, "policy"),
						resource.TestCheckResourceAttrSet(replicateMultiRegionLocalKeyMax, "key_id"),
						// resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMax, "key_material_origin", "cckm"),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMax, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(replicateMultiRegionLocalKeyMax, "key_state", "Enabled"),
					),
				},
			},
		})
	})
}

func TestCckmAwsUploadLocalKey(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	uploadKeyConfig := `
		resource "ciphertrust_cm_key" "cm_key_min" {
		  name      = "%s"
		  algorithm = "AES"
		}

		resource "ciphertrust_aws_key" "aws_key_min" {
		  alias   = ["%s"]
		  kms     = ciphertrust_aws_kms.kms.id
		  region  = ciphertrust_aws_kms.kms.regions[0]
		  upload_key {
			source_key_identifier = ciphertrust_cm_key.cm_key_min.id
		  }
		}

		resource "ciphertrust_cm_key" "cm_key_max" {
		  name      = "%s"
		  algorithm = "AES"
		  # key_size = 128
		  undeletable = false
		  unexportable = false
		  usage_mask = 12
		}

		resource "ciphertrust_aws_key" "aws_key_max" {
		  alias   = ["%s"]
		  kms     = ciphertrust_aws_kms.kms.id
		  region  = ciphertrust_aws_kms.kms.regions[0]
		  upload_key {
			key_expiration        = true
			source_key_identifier = ciphertrust_cm_key.cm_key_max.id
			valid_to              = "%s"
			source_key_tier		  = "local"
		  }
		  key_policy {
            policy = <<-EOT
              %s
            EOT
          }
	 	 tags = {
			TagKey = "UploadSymmetricLocalKey_TagValue"
		  }
		}`

	updateUploadKeyConfig := `
		resource "ciphertrust_cm_key" "cm_key_min" {
		  name      = "%s"
		  algorithm = "AES"
		  undeletable = false
		# remove_from_state_on_destroy = true
		  unexportable = false
		}

		resource "ciphertrust_aws_key" "aws_key_min" {
		  alias   = ["%s"]
		  kms     = ciphertrust_aws_kms.kms.id
		  region  = ciphertrust_aws_kms.kms.regions[0]
		  upload_key {
			key_expiration        = true
			source_key_identifier = ciphertrust_cm_key.cm_key_min.id
			valid_to              = "%s"
			source_key_tier		  = "local"
		  }
		}

		resource "ciphertrust_cm_key" "cm_key_max" {
		  name      = "%s"
		  algorithm = "AES"
		# key_size = 128
		  undeletable = false
		# remove_from_state_on_destroy = true
		  unexportable = false
		  usage_mask = 12
		}

		resource "ciphertrust_aws_key" "aws_key_max" {
		  alias   = ["%s"]
		  kms     = ciphertrust_aws_kms.kms.id
		  region  = ciphertrust_aws_kms.kms.regions[0]
		  upload_key {
			key_expiration        = true
			source_key_identifier = ciphertrust_cm_key.cm_key_max.id
			valid_to              = "%s"
			source_key_tier		  = "local"
		  }
		  key_policy {
	        policy = <<-EOT
	          %s
	        EOT
	      }
	 	 tags = {
			TagKey = "UpdateUploadSymmetricLocalKey_TagValue"
		  }
		}`

	cmKeyMin := cckmKeyNamePrefix + guuid.New().String()
	cmKeyMax := cckmKeyNamePrefix + guuid.New().String()
	localKeyNameMin := awsKeyNamePrefix + guuid.New().String()
	localKeyNameMax := awsKeyNamePrefix + guuid.New().String()
	utc, _ := time.LoadLocation("UTC")
	validTo := time.Now().In(utc).AddDate(0, 0, 1).Format(time.RFC3339)
	validToUpdate := time.Now().In(utc).AddDate(0, 0, 1).Format(time.RFC3339)
	resourceNameMin := "ciphertrust_aws_key.aws_key_min"
	resourceNameMax := "ciphertrust_aws_key.aws_key_max"

	uploadConfig := awsConnectionResource + fmt.Sprintf(uploadKeyConfig, cmKeyMin, localKeyNameMin, cmKeyMax, localKeyNameMax, validTo, awsKeyPolicy)
	updateConfig := awsConnectionResource + fmt.Sprintf(updateUploadKeyConfig, cmKeyMin, localKeyNameMin, validTo, cmKeyMax, localKeyNameMax, validToUpdate, awsKeyPolicy)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: uploadConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceNameMin, "key_id"),
					resource.TestCheckResourceAttr(resourceNameMin, "key_state", "Enabled"),
					// resource.TestCheckResourceAttr(resourceNameMin, "key_size", "256"),
					resource.TestCheckResourceAttr(resourceNameMin, "alias.0", localKeyNameMin),
					resource.TestCheckResourceAttr(resourceNameMin, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceNameMin, "local_key_name", cmKeyMin),

					resource.TestCheckResourceAttrSet(resourceNameMax, "key_id"),
					resource.TestCheckResourceAttr(resourceNameMax, "key_state", "Enabled"),
					// resource.TestCheckResourceAttr(resourceNameMax, "key_size", "128"),
					resource.TestCheckResourceAttr(resourceNameMax, "alias.0", localKeyNameMax),
					resource.TestCheckResourceAttr(resourceNameMin, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceNameMax, "local_key_name", cmKeyMax),
					// resource.TestCheckResourceAttr(resourceNameMax, "key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttrSet(resourceNameMax, "policy"),
					resource.TestCheckResourceAttr(resourceNameMax, "tags.TagKey", "UploadSymmetricLocalKey_TagValue"),
					resource.TestCheckResourceAttr(resourceNameMax, "tags.%", "1"),
				),
			},
			{
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceNameMin, "key_id"),
					resource.TestCheckResourceAttr(resourceNameMin, "key_state", "Enabled"),
					// resource.TestCheckResourceAttr(resourceNameMin, "key_size", "256"),
					resource.TestCheckResourceAttr(resourceNameMin, "alias.0", localKeyNameMin),
					resource.TestCheckResourceAttr(resourceNameMin, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceNameMin, "local_key_name", cmKeyMin),

					resource.TestCheckResourceAttrSet(resourceNameMax, "key_id"),
					resource.TestCheckResourceAttr(resourceNameMax, "key_state", "Enabled"),
					// resource.TestCheckResourceAttr(resourceNameMax, "key_size", "128"),
					resource.TestCheckResourceAttr(resourceNameMax, "alias.0", localKeyNameMax),
					resource.TestCheckResourceAttr(resourceNameMax, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceNameMax, "local_key_name", cmKeyMax),
					// resource.TestCheckResourceAttr(resourceNameMax, "key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttrSet(resourceNameMax, "policy"),
					resource.TestCheckResourceAttr(resourceNameMax, "tags.TagKey", "UpdateUploadSymmetricLocalKey_TagValue"),
					resource.TestCheckResourceAttr(resourceNameMax, "tags.%", "1"),
				),
			},
		},
	})
}

func TestCckmAwsUpdateAlias(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	// No alias
	createConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	// add local.Alias
	addFirstAliasConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	// add alias2, alias3
	addSecondAndThirdAliasesConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias, "%s", "%s"]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	// remove local.Alias
	removeFirstAliasConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s", "%s"]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	// remove alias2
	removeSecondAliasConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s"]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	// remove alias3
	removeThirdAliasConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = []
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	alias2 := awsKeyNamePrefix + "alias-2-" + guuid.New().String()
	alias3 := awsKeyNamePrefix + "alias-3-" + guuid.New().String()
	resourceName := "ciphertrust_aws_key.aws_key"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "0"),
				),
			},
			{
				Config: awsConnectionResource + addFirstAliasConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(addSecondAndThirdAliasesConfig, alias2, alias3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "3"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(removeFirstAliasConfig, alias2, alias3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "2"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(removeSecondAliasConfig, alias3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "alias.0", alias3),
				),
			},
			{
				Config: awsConnectionResource + removeThirdAliasConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "0"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(addSecondAndThirdAliasesConfig, alias2, alias3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "3"),
				),
			},
		},
	})
}

func TestCckmAwsEnableDisableKey(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	disableKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias       = [local.alias]
			customer_master_key_spec = "RSA_2048"
			enable_key = false
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	enableKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias        = [local.alias]
			customer_master_key_spec = "RSA_2048"
			enable_key  = true
			kms         = ciphertrust_aws_kms.kms.id
			region      = ciphertrust_aws_kms.kms.regions[0]
		}`

	resourceName := "ciphertrust_aws_key.aws_key"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "enable_key", "true"),
				),
			},
			{
				Config: awsConnectionResource + disableKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "enable_key", "false"),
				),
			},
			{
				Config: awsConnectionResource + enableKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "enable_key", "true"),
				),
			},
		},
	})
}

func TestCckmAwsUpdateDescription(t *testing.T) {

	t.Run("Add Description", func(t *testing.T) {
		awsConnectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		createKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s"]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`
		addKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s"]
			customer_master_key_spec = "RSA_2048"
			description = "TestAccAwsKey_UpdateDescription new description"
			kms         = ciphertrust_aws_kms.kms.id
			region      = ciphertrust_aws_kms.kms.regions[0]
		}`

		resourceName := "ciphertrust_aws_key.aws_key"
		aliasName := awsKeyNamePrefix + guuid.New().String()
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, aliasName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "description", ""),
					),
				},
				{
					Config: awsConnectionResource + fmt.Sprintf(addKeyConfig, aliasName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "description", "TestAccAwsKey_UpdateDescription new description"),
					),
				},
			},
		})

	})
	t.Run("Remove Description", func(t *testing.T) {
		awsConnectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		createKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s"]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
			description = "TestAccAwsKey_UpdateDescription new description"
		}`
		removeDescriptionConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s"]
			customer_master_key_spec = "RSA_2048"
			kms     = ciphertrust_aws_kms.kms.id
			region  = ciphertrust_aws_kms.kms.regions[0]
		}`
		resourceName := "ciphertrust_aws_key.aws_key"
		aliasName := awsKeyNamePrefix + guuid.New().String()

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, aliasName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
						resource.TestCheckResourceAttr(resourceName, "description", "TestAccAwsKey_UpdateDescription new description"),
					),
				},
				{
					Config: awsConnectionResource + fmt.Sprintf(removeDescriptionConfig, aliasName),
					// ExpectError: regexp.MustCompile("once set, ciphertrust_aws_key.description can only be changed, not removed"),
				},
			},
		})

	})

	t.Run("Change Description", func(t *testing.T) {
		awsConnectionResource, ok := initCckmAwsTest()
		if !ok {
			t.Skip()
		}
		createKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s"]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
			description = "TestAccAwsKey_UpdateDescription new description"
		}`
		changeDescriptionConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = ["%s"]
			customer_master_key_spec = "RSA_2048"
			description = "a different description"
			kms     = ciphertrust_aws_kms.kms.id
			region  = ciphertrust_aws_kms.kms.regions[0]
		}`
		resourceName := "ciphertrust_aws_key.aws_key"
		aliasName := awsKeyNamePrefix + guuid.New().String()

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, aliasName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourceName, "description", "TestAccAwsKey_UpdateDescription new description"),
					),
				},
				{
					Config: awsConnectionResource + fmt.Sprintf(changeDescriptionConfig, aliasName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(resourceName, "description", "a different description"),
					),
				},
			},
		})

	})
}

func TestCckmAwsAddRemoveTags(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	createKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias]
			customer_master_key_spec = "RSA_2048"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	addTagsConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias   = [local.alias]
			customer_master_key_spec = "RSA_2048"
			kms     = ciphertrust_aws_kms.kms.id
			region  = ciphertrust_aws_kms.kms.regions[0]
			tags = {
			  TagKey1 = "AddRemoveTags_TagValue1"
			  TagKey2 = "AddRemoveTags_TagValue2"
			}
		}`

	removeOneTagConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias  = [local.alias]
			customer_master_key_spec = "RSA_2048"
			kms    = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			tags = {
			  TagKey2 = "AddRemoveTags_TagValue2"
			}
		}`

	removeAllTagsConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias    = [local.alias]
			customer_master_key_spec = "RSA_2048"
			kms      = ciphertrust_aws_kms.kms.id
			region   = ciphertrust_aws_kms.kms.regions[0]
			tags = {}
		}`

	resourceName := "ciphertrust_aws_key.aws_key"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tags.%", "0"),
				),
			},
			{
				Config: awsConnectionResource + addTagsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "AddRemoveTags_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "AddRemoveTags_TagValue2"),
				),
			},
			{
				Config: awsConnectionResource + removeOneTagConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "AddRemoveTags_TagValue2"),
				),
			},
			{
				Config: awsConnectionResource + removeAllTagsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tags.%", "0"),
				),
			},
			{
				Config: awsConnectionResource + addTagsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "AddRemoveTags_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "AddRemoveTags_TagValue2"),
				),
			},
		},
	})
}

func TestCckmAwsEnableDisableRotationJob(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createKeyConfig := `
		resource "ciphertrust_scheduler" "scheduled_rotation_job" {
		  end_date = "2026-03-07T14:24:00Z"
		  cckm_key_rotation_params {
			cloud_name = "aws"
		  }
		  name       = "TerraformTest"
		  operation  = "cckm_key_rotation"
		  run_at     = "0 9 * * sat"
		  run_on     = "any"
		  start_date = "2025-03-07T14:24:00Z"
		}

		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias, "%s"]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	enableRotationConfig := `
		resource "ciphertrust_scheduler" "scheduled_rotation_job" {
		  end_date = "2026-03-07T14:24:00Z"
		  cckm_key_rotation_params {
			cloud_name = "aws"
		  }
		  name       = "TerraformTest"
		  operation  = "cckm_key_rotation"
		  run_at     = "0 9 * * sat"
		  run_on     = "any"
		  start_date = "2025-03-07T14:24:00Z"
		}

		resource "ciphertrust_aws_key" "aws_key" {
		  alias      = [local.alias, "%s"]
		  enable_rotation {
			job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
			key_source    = "ciphertrust"
		  }
		  customer_master_key_spec = "SYMMETRIC_DEFAULT"
		  kms        = ciphertrust_aws_kms.kms.id
		  region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	disableRotationConfig := `
		resource "ciphertrust_scheduler" "scheduled_rotation_job" {
		  end_date = "2026-03-07T14:24:00Z"
		  cckm_key_rotation_params {
			cloud_name = "aws"
		  }
		  name       = "TerraformTest"
		  operation  = "cckm_key_rotation"
		  run_at     = "0 9 * * sat"
		  run_on     = "any"
		  start_date = "2025-03-07T14:24:00Z"
		}

		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias, "%s"]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	deleteSchedulerConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias, "%s"]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	alias2 := awsKeyNamePrefix + guuid.New().String()
	resourceName := "ciphertrust_aws_key.aws_key"
	schedulerResourceName := "ciphertrust_scheduler.scheduled_rotation_job"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, alias2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(schedulerResourceName, "id"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(enableRotationConfig, alias2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(schedulerResourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "labels.auto_rotate_key_source", "ciphertrust"),
					testAwsVerifySceduleridAndJobConfig(schedulerResourceName, resourceName),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(disableRotationConfig, alias2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(schedulerResourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "labels.%", "0"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(deleteSchedulerConfig, alias2),
				Check: resource.ComposeTestCheckFunc(
					testAccVerifyResourceDeleted("ciphertrust_scheduler"),
				),
			},
		},
	})
}

func TestCckmAwsEnableAndDisableAutoRotation(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// createKeyConfig := `
	// 	resource "ciphertrust_scheduler" "scheduled_rotation_job" {
	// 	  end_date = "2026-03-07T14:24:00Z"
	// 	  cckm_key_rotation_params {
	// 		cloud_name = "aws"
	// 	  }
	// 	  name       = "TerraformTest"
	// 	  operation  = "cckm_key_rotation"
	// 	  run_at     = "0 9 * * sat"
	// 	  run_on     = "any"
	// 	  start_date = "2025-03-07T14:24:00Z"
	// 	}

	// 	resource "ciphertrust_aws_key" "aws_key" {
	// 		alias      = [local.alias, "%s"]
	// 		customer_master_key_spec = "SYMMETRIC_DEFAULT"
	// 		kms        = ciphertrust_aws_kms.kms.id
	// 		region     = ciphertrust_aws_kms.kms.regions[0]
	// 		enable_rotation {
	// 		  job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
	// 		  key_source    = "ciphertrust"
	// 	  }
	// 	}`

	enableAutoRotation := `
			resource "ciphertrust_scheduler" "scheduled_rotation_job" {
		  	end_date = "2026-03-07T14:24:00Z"
		  	cckm_key_rotation_params {
				cloud_name = "aws"
		  	}
		  	name       = "TerraformTest"
		  	operation  = "cckm_key_rotation"
		  	run_at     = "0 9 * * sat"
		  	run_on     = "any"
		  	start_date = "2025-03-07T14:24:00Z"
		}
		resource "ciphertrust_aws_key" "aws_key" {
			alias      = [local.alias, "%s"]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			kms        = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
			auto_rotate = true
			enable_rotation {
			  job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
			  key_source    = "ciphertrust"
			}	
		}`

	alias2 := awsKeyNamePrefix + guuid.New().String()
	resourceName := "ciphertrust_aws_key.aws_key"
	schedulerResourceName := "ciphertrust_scheduler.scheduled_rotation_job"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// {
			// 	Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, alias2),
			// 	Check: resource.ComposeTestCheckFunc(
			// 		resource.TestCheckResourceAttrSet(schedulerResourceName, "id"),
			// 		resource.TestCheckResourceAttr(resourceName, "auto_rotate", "false"),
			// 	),
			// },
			{
				Config: awsConnectionResource + fmt.Sprintf(enableAutoRotation, alias2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(schedulerResourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "auto_rotate", "true"),
				),
			},
		},
	})
}
