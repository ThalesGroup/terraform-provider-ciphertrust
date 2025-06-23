package provider

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	awsKeyNamePrefix    = "tf-aws-"
	awsPolicyUserPrefix = "arn:aws:iam::556782317223:user/"
	awsPolicyRolePrefix = "arn:aws:iam::556782317223:role/"
)

var (
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

func initCckmAwsTest(timeout ...int) (string, bool) {
	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if awsAccessKeyID == "" || awsSecretAccessKey == "" {
		return "", false
	}
	operationTimeout := defaultAwsOperationTimeout
	if timeout != nil && len(timeout) > 1 {
		operationTimeout = timeout[0]
	}
	awsConfig := `
		provider "ciphertrust" {
			aws_operation_timeout = %d
		}
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection  = ciphertrust_aws_connection.aws_connection.id
			name           = "%s"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[0],
				data.ciphertrust_aws_account_details.account_details.regions[1],
				data.ciphertrust_aws_account_details.account_details.regions[2]
			]
		}
		locals {
			alias   = "%s"
			cmKeyName = "%s"
		}`
	uid := "tf-" + uuid.New().String()[:8]
	awsConnectionResource := fmt.Sprintf(awsConfig, operationTimeout, uid, uid, uid, uid)
	return awsConnectionResource, true
}

func getAwsUsers() []string {
	users := os.Getenv("AWS_KEY_USERS")
	ret := strings.Split(users, ",")
	return ret
}

func getAwsRoles() []string {
	roles := os.Getenv("AWS_KEY_ROLES")
	ret := strings.Split(roles, ",")
	return ret
}

// TestCckmAwsKeyNative tests creating native keys and update functionality
func TestCckmAwsKeyNative(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	awsKeyUsers := getAwsUsers()
	if len(awsKeyUsers) != 2 {
		t.Skip("AWS_KEY_USERS is not exported or doesn't contain 2 roles")
	}
	awsKeyRoles := getAwsRoles()
	if len(awsKeyRoles) != 2 {
		t.Skip("AWS_KEY_ROLES is not exported or doesn't contain 2 users")
	}

	createKeyConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params {
				cloud_name = "aws"
			}
			end_date = "2027-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_aws_key" "native_key" {
			alias        = [local.alias, "%s", "%s"]
			auto_rotate  = true
			auto_rotation_period_in_days = 256
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			description  = "create description"
			enable_key   = true
			enable_rotation {
				job_config_id = ciphertrust_scheduler.scheduler.id
				key_source    = "ciphertrust"
			}
			key_policy {
				key_admins  = ["%s"]
				key_users   = ["%s"]
				key_admins_roles  = ["%s"]
				key_users_roles   = ["%s"]
			}
			key_usage    = "ENCRYPT_DECRYPT"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}
		}`
	updateKeyConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params {
				cloud_name = "aws"
			}
			end_date = "2027-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_scheduler" "scheduler_two" {
			cckm_key_rotation_params {
				cloud_name = "aws"
			}
			end_date = "2027-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_aws_key" "native_key" {
			auto_rotate = true
			auto_rotation_period_in_days = 128
			alias        = [local.alias]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			description  = "update description"
			enable_key   = false
			enable_rotation {
				job_config_id = ciphertrust_scheduler.scheduler_two.id
				key_source    = "ciphertrust"
			}
			key_policy {
				policy = <<-EOT
					%s
				EOT
			}
			key_usage = "ENCRYPT_DECRYPT"
			kms       = ciphertrust_aws_kms.kms.id
			region    = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey3 = "TagValue3"
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}
		}`
	updateKeyConfig2 := `
		variable "policy" {
			type    = string
			default = <<-EOT
					{"Version":"2012-10-17","Id":"kms-tf-1","Statement":[{"Sid":"Enable IAM User Permissions 1","Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*"}]}
			EOT
		}
		resource "ciphertrust_aws_policy_template" "policy_template" {
			kms    = ciphertrust_aws_kms.kms.id
			name   = "%s"
			policy = var.policy
		}
		resource "ciphertrust_aws_key" "native_key" {
			alias        = [local.alias]
			auto_rotate  = false
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			description  = "create description"
			enable_key   = true
			key_usage    = "ENCRYPT_DECRYPT"
			key_policy {
				policy_template = ciphertrust_aws_policy_template.policy_template.id
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}
		}`
	updateKeyConfig3 := `
		resource "ciphertrust_aws_key" "native_key" {
			alias        = [local.alias]
			auto_rotate  = false
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			description  = "create description"
			enable_key   = false
			key_usage    = "ENCRYPT_DECRYPT"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {}
		}`
	aliasList := []string{
		awsKeyNamePrefix + uuid.New().String(),
		awsKeyNamePrefix + uuid.New().String(),
	}
	keyResource := "ciphertrust_aws_key.native_key"
	schedulerOneName := "tf-" + uuid.NewString()[:8]
	schedulerTwoName := "tf-" + uuid.NewString()[:8]
	policyTemplateName := "tf-" + uuid.NewString()[:8]
	schedulerTwoResource := "ciphertrust_scheduler.scheduler_two"
	//policyTemplateResource := "ciphertrust_aws_policy_template.policy_template"

	createKeyConfigStr := fmt.Sprintf(createKeyConfig, schedulerOneName, aliasList[0], aliasList[1], awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1])
	updateKeyConfigStr := fmt.Sprintf(updateKeyConfig, schedulerOneName, schedulerTwoName, awsKeyPolicy)
	updateKeyConfigStr2 := fmt.Sprintf(updateKeyConfig2, policyTemplateName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "arn"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", "256"),
					resource.TestCheckResourceAttr(keyResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "enabled", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "key_id"),
					resource.TestCheckResourceAttr(keyResource, "key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "ciphertrust"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey2", "TagValue2"),
					testCheckAttributeContains(keyResource, "policy", append(awsKeyUsers, awsKeyRoles...), true),
				),
			},
			{
				Config: awsConnectionResource + updateKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", "128"),
					resource.TestCheckResourceAttr(keyResource, "description", "update description"),
					resource.TestCheckResourceAttr(keyResource, "enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admin.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Disabled"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admin_roles.#", "0"),
					resource.TestCheckResourceAttrPair(keyResource, "labels.job_config_id", schedulerTwoResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "3"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey2", "TagValue2"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey3", "TagValue3"),
					testCheckAttributeContains(keyResource, "policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				Config: awsConnectionResource + createKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "arn"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", "256"),
					resource.TestCheckResourceAttr(keyResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "enabled", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "key_id"),
					resource.TestCheckResourceAttr(keyResource, "key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey2", "TagValue2"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "ciphertrust"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					testCheckAttributeContains(keyResource, "policy", append(awsKeyUsers, awsKeyRoles...), true),
				),
			},
			{
				Config: awsConnectionResource + updateKeyConfigStr2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "2"),
					//resource.TestCheckResourceAttrPair(keyResource, "tags.cckm_policy_template_id", policyTemplateResource, "id"),
					testCheckAttributeContains(keyResource, "policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				Config: awsConnectionResource + updateKeyConfig3,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Disabled"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "0"),
				),
			},
		},
	})
}

func TestCckmAwsKeyImportKeyMaterial(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	t.Run("LocalSourceKeyTier", func(t *testing.T) {
		importKeys := `
		resource "ciphertrust_aws_key" "aes" {
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration = true
				valid_to = "%s"
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_key" "rsa2048" {
			customer_master_key_spec = "RSA_2048"
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration = false
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_key" "ec_p521" {
			customer_master_key_spec = "ECC_NIST_P521"
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}`
		aesKeyResource := "ciphertrust_aws_key.aes"
		rsaKeyResource := "ciphertrust_aws_key.rsa2048"
		ecKeyResource := "ciphertrust_aws_key.ec_p521"

		aesCmKeyName := "tf-aes-" + uuid.NewString()[:]
		rsaCmKeyName := "tf-rsa-" + uuid.NewString()[:]
		ecCmKeyName := "tf-ec_p521-" + uuid.NewString()[:]

		validTo := time.Now().UTC().AddDate(0, 0, 1).Format(time.RFC3339)

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: awsConnectionResource + fmt.Sprintf(importKeys, aesCmKeyName, validTo, rsaCmKeyName, ecCmKeyName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(aesKeyResource, "expiration_model", "KEY_MATERIAL_EXPIRES"),
						resource.TestCheckResourceAttr(aesKeyResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
						resource.TestCheckResourceAttrSet(aesKeyResource, "id"),
						resource.TestCheckResourceAttrSet(aesKeyResource, "key_id"),
						resource.TestCheckResourceAttr(aesKeyResource, "key_material_origin", "cckm"),
						resource.TestCheckResourceAttr(aesKeyResource, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(rsaKeyResource, "valid_to", ""),
						testCheckAttributeContains(aesKeyResource, "valid_to", []string{validTo}, true),

						resource.TestCheckResourceAttr(rsaKeyResource, "expiration_model", "KEY_MATERIAL_DOES_NOT_EXPIRE"),
						resource.TestCheckResourceAttr(rsaKeyResource, "customer_master_key_spec", "RSA_2048"),
						resource.TestCheckResourceAttrSet(rsaKeyResource, "id"),
						resource.TestCheckResourceAttrSet(rsaKeyResource, "key_id"),
						resource.TestCheckResourceAttr(rsaKeyResource, "key_material_origin", "cckm"),
						resource.TestCheckResourceAttr(rsaKeyResource, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(rsaKeyResource, "valid_to", ""),

						resource.TestCheckResourceAttr(ecKeyResource, "expiration_model", "KEY_MATERIAL_DOES_NOT_EXPIRE"),
						resource.TestCheckResourceAttr(ecKeyResource, "customer_master_key_spec", "ECC_NIST_P521"),
						resource.TestCheckResourceAttrSet(ecKeyResource, "id"),
						resource.TestCheckResourceAttrSet(ecKeyResource, "key_id"),
						resource.TestCheckResourceAttr(ecKeyResource, "key_material_origin", "cckm"),
						resource.TestCheckResourceAttr(ecKeyResource, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(rsaKeyResource, "valid_to", ""),
					),
				},
			},
		})
	})
}

func TestCckmAwsKeyUpload(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	uploadKeys := `
		resource "ciphertrust_cm_key" "cm_key" {
			name      = local.cmKeyName
			algorithm = "RSA"
			key_size  = 2048
		}
		resource "ciphertrust_aws_key" "upload_local_key" {
			alias   = [local.alias]
			customer_master_key_spec = "RSA_2048"
			description  = "upload description"
			kms     = ciphertrust_aws_kms.kms.id
			region  = ciphertrust_aws_kms.kms.regions[0]
			upload_key {
				key_expiration        = true
				source_key_identifier = ciphertrust_cm_key.cm_key.id
				valid_to              = "%s"
				source_key_tier		  = "local"
			}
			key_policy {
				policy = <<-EOT
				  %s
				EOT
			}
			tags = {
				UploadTagKey = "UploadTagValue"
			}
		}`

	validTo := time.Now().UTC().AddDate(0, 0, 1).Format(time.RFC3339)
	localKeyResource := "ciphertrust_aws_key.upload_local_key"

	uploadConfig := awsConnectionResource + fmt.Sprintf(uploadKeys, validTo, awsKeyPolicy)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: uploadConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(localKeyResource, "alias.#", "1"),
					resource.TestCheckResourceAttr(localKeyResource, "description", "upload description"),
					resource.TestCheckResourceAttrSet(localKeyResource, "id"),
					resource.TestCheckResourceAttrSet(localKeyResource, "key_id"),
					resource.TestCheckResourceAttr(localKeyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(localKeyResource, "key_id"),
					resource.TestCheckResourceAttr(localKeyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(localKeyResource, "key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttrSet(localKeyResource, "policy"),
					resource.TestCheckResourceAttr(localKeyResource, "tags.%", "1"),
					resource.TestCheckResourceAttr(localKeyResource, "tags.UploadTagKey", "UploadTagValue"),
				),
			},
		},
	})
}

func TestCckmAwsKeyMultiRegion(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	awsKeyUsers := getAwsUsers()
	if len(awsKeyUsers) != 2 {
		t.Skip("AWS_KEY_USERS is not exported or doesn't contain 2 roles")
	}
	awsKeyRoles := getAwsRoles()
	if len(awsKeyRoles) != 2 {
		t.Skip("AWS_KEY_ROLES is not exported or doesn't contain 2 users")
	}

	t.Run("Native", func(t *testing.T) {
		createConfig := `
			resource "ciphertrust_aws_key" "multi_region_key" {
				alias                    = ["%s", "%s"]
				customer_master_key_spec = "RSA_2048"
				key_usage                = "SIGN_VERIFY"
				kms                      = ciphertrust_aws_kms.kms.id
				region                   = ciphertrust_aws_kms.kms.regions[0]
				tags = {
					CreateTagKey1 = "CreateTagValue1"
					CreateTagKey2 = "CreateTagValue2"
				}
				multi_region = true
			}
			resource "ciphertrust_aws_key" "replica"{
				depends_on = [
					ciphertrust_aws_key.multi_region_key,
				]
				alias = ["%s"]
				key_policy {
					key_admins        = ["%s"]
					key_users         = ["%s"]
					key_admins_roles  = ["%s"]
					key_users_roles   = ["%s"]
				}
				region 					= ciphertrust_aws_kms.kms.regions[1]
				description 			= "replica one"
				origin					= "AWS_KMS"
				tags = {
					RegionOneTagKey = "RegionOneTagValue"
				}
				replicate_key {
					key_id 				= ciphertrust_aws_key.multi_region_key.key_id
					make_primary 		= true
				}
			}`
		updateConfig := `
			resource "ciphertrust_aws_key" "multi_region_key" {
				alias                    = ["%s", "%s"]
				customer_master_key_spec = "RSA_2048"
				key_usage                = "SIGN_VERIFY"
				kms                      = ciphertrust_aws_kms.kms.id
				region                   = ciphertrust_aws_kms.kms.regions[0]
				tags = {
					CreateTagKey1 = "CreateTagValue1"
					CreateTagKey2 = "CreateTagValue2"
				}
				multi_region = true
			}
			resource "ciphertrust_aws_key" "replica"{
				alias = ["%s"]
				key_policy {
					key_admins        = ["%s"]
					key_users         = ["%s"]
					key_admins_roles  = ["%s"]
					key_users_roles   = ["%s"]
				}
				region 					= ciphertrust_aws_kms.kms.regions[1]
				description 			= "replica one"
				origin					= "AWS_KMS"
				primary_region			= ciphertrust_aws_kms.kms.regions[0]
				tags = {
					RegionOneTagKey = "RegionOneTagValue"
				}
				replicate_key {
					key_id 				= ciphertrust_aws_key.multi_region_key.key_id
				}
			}`
		aliasA := awsKeyNamePrefix + uuid.New().String()[8:]
		aliasB := awsKeyNamePrefix + uuid.New().String()[8:]
		replicaAlias := awsKeyNamePrefix + uuid.New().String()[8:]
		keyResource := "ciphertrust_aws_key.multi_region_key"
		replicaResource1 := "ciphertrust_aws_key.replica"
		createResources := awsConnectionResource + fmt.Sprintf(createConfig, aliasA, aliasB,
			replicaAlias, awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1])
		updateResources := awsConnectionResource + fmt.Sprintf(updateConfig, aliasA, aliasB,
			replicaAlias, awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1])
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createResources,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(keyResource, "alias.#", "2"),
						resource.TestCheckResourceAttr(keyResource, "customer_master_key_spec", "RSA_2048"),
						resource.TestCheckResourceAttrSet(keyResource, "id"),
						resource.TestCheckResourceAttr(keyResource, "multi_region", "true"),
						resource.TestCheckResourceAttr(keyResource, "multi_region_replica_keys.#", "0"),
						resource.TestCheckResourceAttrSet(keyResource, "policy"),
						resource.TestCheckResourceAttr(keyResource, "tags.%", "2"),
						resource.TestCheckResourceAttr(keyResource, "tags.CreateTagKey1", "CreateTagValue1"),
						resource.TestCheckResourceAttr(keyResource, "tags.CreateTagKey2", "CreateTagValue2"),

						resource.TestCheckResourceAttr(replicaResource1, "alias.#", "1"),
						resource.TestCheckResourceAttr(replicaResource1, "alias.0", replicaAlias),
						resource.TestCheckResourceAttr(replicaResource1, "description", "replica one"),
						resource.TestCheckResourceAttrSet(replicaResource1, "id"),
						resource.TestCheckResourceAttr(replicaResource1, "key_admins.#", "1"),
						resource.TestCheckResourceAttr(replicaResource1, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
						resource.TestCheckResourceAttr(replicaResource1, "key_users.#", "1"),
						resource.TestCheckResourceAttr(replicaResource1, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
						resource.TestCheckResourceAttr(replicaResource1, "key_admins_roles.#", "1"),
						resource.TestCheckResourceAttr(replicaResource1, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
						resource.TestCheckResourceAttr(replicaResource1, "key_users_roles.#", "1"),
						resource.TestCheckResourceAttr(replicaResource1, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
						resource.TestCheckResourceAttr(replicaResource1, "multi_region", "true"),
						resource.TestCheckResourceAttr(replicaResource1, "multi_region_replica_keys.#", "1"),
						resource.TestCheckResourceAttrSet(replicaResource1, "policy"),
						resource.TestCheckResourceAttr(replicaResource1, "tags.%", "1"),
						resource.TestCheckResourceAttr(replicaResource1, "tags.RegionOneTagKey", "RegionOneTagValue"),
						// Sometimes - this is true
						//resource.TestCheckResourceAttr(replicaResource1, "multi_region_key_type", "PRIMARY"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(
							replicaResource1,
							tfjsonpath.New("policy"),
							knownvalue.StringRegexp(regexp.MustCompile(awsKeyUsers[0]))),
					},
				},
				{
					Config: updateResources,
					Check:  resource.ComposeTestCheckFunc(
					// On return of the API the replicated key the previous primary key will be a replica (primary_region) - sometimes
					//resource.TestCheckResourceAttr(keyResource, "multi_region_key_type", "PRIMARY"),
					),
				},
			},
		})
	})
	t.Run("LocalKey", func(t *testing.T) {
		createConfig := `
			resource "ciphertrust_cm_key" "cm_key" {
				name      = local.cmKeyName
				algorithm = "RSA"
				key_size  = 2048
			}
			resource "ciphertrust_aws_key" "multi_region_key" {
				alias                    = [local.alias]
				customer_master_key_spec = "RSA_2048"
				kms                      = ciphertrust_aws_kms.kms.id
				region  = ciphertrust_aws_kms.kms.regions[0]
				upload_key {
					source_key_identifier = ciphertrust_cm_key.cm_key.id
					source_key_tier		  = "local"
				}
				multi_region = true
			}`
		replicateConfig := `
			resource "ciphertrust_cm_key" "cm_key" {
				name      = local.cmKeyName
				algorithm = "RSA"
				key_size  = 2048
			}
			resource "ciphertrust_aws_key" "multi_region_key" {
				alias                    = [local.alias]
				customer_master_key_spec = "RSA_2048"
				kms                      = ciphertrust_aws_kms.kms.id
				region  = ciphertrust_aws_kms.kms.regions[0]
				upload_key {
					source_key_identifier = ciphertrust_cm_key.cm_key.id
					source_key_tier		  = "local"
				}
				multi_region = true
			}
			resource "ciphertrust_aws_key" "replica"{
				alias                    = [local.alias]
				region 					= ciphertrust_aws_kms.kms.regions[1]
				replicate_key {
					key_expiration        = true
					key_id 				= ciphertrust_aws_key.multi_region_key.key_id
					import_key_material = true
					valid_to              = "%s"
				}
			}`
		cmKeyResource := "ciphertrust_cm_key.cm_key"
		awsKeyResource := "ciphertrust_aws_key.multi_region_key"
		replicaResource := "ciphertrust_aws_key.replica"
		createConfigStr := awsConnectionResource + createConfig
		validTo := time.Now().UTC().AddDate(0, 0, 1).Format(time.RFC3339)
		replicateConfigStr := awsConnectionResource + fmt.Sprintf(replicateConfig, validTo)
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: createConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrPair(awsKeyResource, "local_key_id", cmKeyResource, "id"),
						resource.TestCheckResourceAttrPair(awsKeyResource, "local_key_name", cmKeyResource, "name"),
						resource.TestCheckResourceAttr(awsKeyResource, "origin", "EXTERNAL"),
					),
				},
				{
					Config: replicateConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrPair(replicaResource, "local_key_id", cmKeyResource, "id"),
						resource.TestCheckResourceAttrPair(replicaResource, "local_key_name", cmKeyResource, "name"),
						resource.TestCheckResourceAttr(replicaResource, "origin", "EXTERNAL"),
						resource.TestCheckResourceAttr(replicaResource, "expiration_model", "KEY_MATERIAL_EXPIRES"),
						testCheckAttributeContains(replicaResource, "valid_to", []string{validTo}, true),
					),
				},
			},
		})
	})
}

// testAccListResourceAttributes can help with test development
func testAccListResourceAttributes(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fmt.Printf("************ %s attributes\n", resourceName)
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
				fmt.Printf("k:%s v:%v\n", k, rs.Primary.Attributes[k])
			}
			fmt.Printf("**************** end %s attributes\n", resourceName)
			return nil
		}
		return fmt.Errorf("error: did not find resource %s so can't list attributes", resourceName)
	}
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

func testCheckAttributeContains(resourceName string, attributeName string, stringsToFind []string, contains bool) resource.TestCheckFunc {
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
			found := false
			for _, k := range keys {
				if k == attributeName {
					found = true
					for _, str := range stringsToFind {
						if contains {
							if !strings.Contains(rs.Primary.Attributes[k], str) {
								return fmt.Errorf("error: %s.%s does not contain %s", resourceName, attributeName, str)
							}
						} else {
							if strings.Contains(rs.Primary.Attributes[k], str) {
								return fmt.Errorf("error: %s.%s does contain %s", resourceName, attributeName, str)
							}
						}
					}
				}
			}
			if !found {
				return fmt.Errorf("error: did not find %s.%s", resourceName, attributeName)
			}
			return nil
		}
		return fmt.Errorf("error: did not find resource %s so can't list attributes", resourceName)
	}
}

func testVerifyResourceDeleted(resourceType string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for _, rs := range s.RootModule().Resources {
			if rs.Type == resourceType {
				return fmt.Errorf("error: resource %s still exists", resourceType)
			}
		}
		return nil
	}
}

func testAccListResources() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for rn, rs := range s.RootModule().Resources {
			fmt.Printf("rn: %s rt: %s\n", rn, rs.Type)
		}
		return nil
	}
}

func TestCckmAwsKeyRotation(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	t.Run("KeyRotation_Native", func(t *testing.T) {
		nativeKey := `
		resource "ciphertrust_aws_key" "native_key" {
			alias        = [local.alias, "%s"]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			description  = "create description"
			key_usage    = "ENCRYPT_DECRYPT"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}
		}
		resource "ciphertrust_aws_key_rotation" "rotate" {
			key_id = ciphertrust_aws_key.native_key.key_id
		}`
		aesNativeKeyResource := "ciphertrust_aws_key_rotation.rotate"
		aesCmKeyRotationName := "tf-aes-key-rotation" + uuid.NewString()[:]

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: awsConnectionResource + fmt.Sprintf(nativeKey, aesCmKeyRotationName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttrSet(aesNativeKeyResource, "id"),
						resource.TestCheckResourceAttrSet(aesNativeKeyResource, "key_id"),
						resource.TestCheckResourceAttrSet(aesNativeKeyResource, "status"),
					),
				},
			},
		})

	})
}
