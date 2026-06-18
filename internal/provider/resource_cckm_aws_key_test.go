package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

	// cmKeyUsageCryptoOps is the CM key usage_mask that allows Sign (1), Verify (2),
	// Encrypt (4), Decrypt (8), Wrap Key (16), and Unwrap Key (32). Used for AES
	// source keys in CCKM BYOK and XKS key tests.
	cmKeyUsageCryptoOps = 63
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

var importStateVerifyIgnoreAwsKey = []string{
	"auto_rotate",
	"enable_rotation",
	"import_key_material",
	"key_policy",
	"kms",
	"labels",
	"multi_region_key_type",
	"multi_region_primary_key",
	"multi_region_replica_keys",
	"next_rotation_date",
	"replicate_key",
	"schedule_for_deletion_days",
	"tags",
	"updated_at",
	"upload_key",
}

// initCckmAwsTest builds the Terraform provider and resource configuration used as a shared setup
// by most CCKM AWS tests. It creates an AWS connection, looks up account details, registers a KMS
// with three regions, and exposes alias and cmKeyName locals for use in each test's own config.
// Returns the config string and true when the required AWS environment variables are set,
// or an empty string and false when they are not (the caller should t.Skip() in that case).
func initCckmAwsTest(timeout ...int) (string, bool) {
	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if awsAccessKeyID == "" || awsSecretAccessKey == "" {
		return "", false
	}
	operationTimeout := defaultAwsOperationTimeout
	if len(timeout) > 0 {
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
			alias             = "%s"
			cmKeyName         = "%s"
			cm_key_usage_mask = %d
		}`
	uid := "tf-" + uuid.New().String()[:8]
	awsConnectionResource := fmt.Sprintf(awsConfig, operationTimeout, uid, uid, uid, uid, cmKeyUsageCryptoOps)
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

// applyCDSPAAS comments out the run_on scheduler attribute when the CDSPAAS
// environment variable is "true". CipherTrust as a Service does not support
// run_on, so it is replaced with a HCL comment in that environment.
func applyCDSPAAS(config string) string {
	if os.Getenv("CDSPAAS") == "true" {
		return strings.ReplaceAll(config, "run_on", "#run_on")
	}
	return config
}

// TestCckmAWSKeyNative tests creating native keys and update functionality
func TestCckmAWSKeyNative(t *testing.T) {
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
			end_date = "2050-03-07T14:24:00Z"
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
            origin       = "AWS_KMS"
		}`
	updateKeyConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params {
				cloud_name = "aws"
			}
			end_date = "2050-03-07T14:24:00Z"
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
			end_date = "2050-03-07T14:24:00Z"
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
			origin       = "AWS_KMS"
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
			origin       = "AWS_KMS"
		}`
	updateKeyConfig3 := `
		resource "ciphertrust_aws_key" "native_key" {
			alias        = [local.alias]
			auto_rotate  = false
			customer_master_key_spec = "%s"
			description  = "create description"
			enable_key   = false
			key_usage    = "ENCRYPT_DECRYPT"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {}
			origin       = "AWS_KMS"
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

	createKeyRotationPeriodInDays := "256"
	updateKeyRotationPeriodInDays := "128"

	createKeyConfigStr := fmt.Sprintf(createKeyConfig, schedulerOneName, aliasList[0], aliasList[1], awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1])
	createKeyConfigStr = applyCDSPAAS(createKeyConfigStr)
	updateKeyConfigStr := fmt.Sprintf(updateKeyConfig, schedulerOneName, schedulerTwoName, awsKeyPolicy)
	updateKeyConfigStr = applyCDSPAAS(updateKeyConfigStr)
	updateKeyConfigStr2 := fmt.Sprintf(updateKeyConfig2, policyTemplateName)
	updateKeyConfig3Str := fmt.Sprintf(updateKeyConfig3, "SYMMETRIC_DEFAULT")
	modifyPlanConfigStr := fmt.Sprintf(updateKeyConfig3, "RSA_2048")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "arn"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", createKeyRotationPeriodInDays),
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
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			{
				Config: awsConnectionResource + updateKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", updateKeyRotationPeriodInDays),
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
					resource.TestCheckResourceAttr(keyResource, "auto_rotation_period_in_days", createKeyRotationPeriodInDays),
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
					resource.TestCheckNoResourceAttr(keyResource, "auto_rotation_period_in_days"),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "2"),
					//resource.TestCheckResourceAttrPair(keyResource, "tags.cckm_policy_template_id", policyTemplateResource, "id"),
					// policy not always updated in time
					// testCheckAttributeContains(keyResource, "policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				Config: awsConnectionResource + updateKeyConfig3Str,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckNoResourceAttr(keyResource, "auto_rotation_period_in_days"),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Disabled"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "0"),
				),
			},
			{
				// Verify ModifyPlan fires an error when customer_master_key_spec is changed.
				Config:      awsConnectionResource + modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
		},
	})
}

func TestCckmAWSKeyImportKeyMaterialLocal(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
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
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
		}
		resource "ciphertrust_aws_key" "rsa2048" {
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration = false
			}
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
            customer_master_key_spec = "RSA_2048"
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
	// modifyPlanEcConfigStr uses a fake source_key_name for ec_p521 to exercise
	// the ModifyPlan immutable-field check without making any real API calls.
	modifyPlanEcConfigStr := awsConnectionResource + fmt.Sprintf(importKeys, aesCmKeyName, validTo, rsaCmKeyName, "tf-fake-ec-key")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
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
					resource.TestCheckResourceAttr(ecKeyResource, "valid_to", ""),
				),
			},
			// Re-apply to let EXTERNAL key material processing settle before import.
			// The checks confirm stable attributes for all three keys so that the
			// subsequent ImportStateVerify steps compare against known-good values.
			{
				Config: awsConnectionResource + fmt.Sprintf(importKeys, aesCmKeyName, validTo, rsaCmKeyName, ecCmKeyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(aesKeyResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(aesKeyResource, "expiration_model", "KEY_MATERIAL_EXPIRES"),
					resource.TestCheckResourceAttr(aesKeyResource, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(aesKeyResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttrSet(aesKeyResource, "id"),
					resource.TestCheckResourceAttrSet(aesKeyResource, "key_id"),

					resource.TestCheckResourceAttr(rsaKeyResource, "customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(rsaKeyResource, "expiration_model", "KEY_MATERIAL_DOES_NOT_EXPIRE"),
					resource.TestCheckResourceAttr(rsaKeyResource, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(rsaKeyResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttrSet(rsaKeyResource, "id"),
					resource.TestCheckResourceAttrSet(rsaKeyResource, "key_id"),

					resource.TestCheckResourceAttr(ecKeyResource, "customer_master_key_spec", "ECC_NIST_P521"),
					resource.TestCheckResourceAttr(ecKeyResource, "expiration_model", "KEY_MATERIAL_DOES_NOT_EXPIRE"),
					resource.TestCheckResourceAttr(ecKeyResource, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(ecKeyResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttrSet(ecKeyResource, "id"),
					resource.TestCheckResourceAttrSet(ecKeyResource, "key_id"),
				),
			},
			{
				// Verify ModifyPlan fires an error when import_key_material.source_key_name is changed.
				Config:      modifyPlanEcConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				ResourceName:            aesKeyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(aesKeyResource, "id"),
			},
			{
				ResourceName:            rsaKeyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(rsaKeyResource, "id"),
			},
			{
				ResourceName:            ecKeyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(ecKeyResource, "id"),
			},
		},
	})
}

func TestCckmAWSKeyUpload(t *testing.T) {
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
				source_key_identifier = %s
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
	uploadConfig := awsConnectionResource + fmt.Sprintf(uploadKeys, "ciphertrust_cm_key.cm_key.id", validTo, awsKeyPolicy)
	modifyPlanConfigStr := awsConnectionResource + fmt.Sprintf(uploadKeys, `"tf-fake-key-id"`, validTo, awsKeyPolicy)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
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
			{
				ResourceName:            localKeyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(localKeyResource, "id"),
			},
			{
				// Verify ModifyPlan fires an error when upload_key.source_key_identifier is changed.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
		},
	})
}

func TestCckmAWSKeyMultiRegionNative(t *testing.T) {
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
                origin       = "AWS_KMS"
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
		PreCheck:                 func() { cleanupCckmAwsKMS() },
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
				// Update state before import as primary region has changed. The Check
				// confirms stable attributes are correct so the subsequent
				// ImportStateVerify steps compare against known-good values.
				Config: createResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "key_id"),
					resource.TestCheckResourceAttr(keyResource, "multi_region", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "tags.CreateTagKey2", "CreateTagValue2"),
					resource.TestCheckResourceAttr(replicaResource1, "alias.#", "1"),
					resource.TestCheckResourceAttrSet(replicaResource1, "id"),
					resource.TestCheckResourceAttrSet(replicaResource1, "key_id"),
					resource.TestCheckResourceAttr(replicaResource1, "multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource1, "policy"),
					resource.TestCheckResourceAttr(replicaResource1, "tags.%", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "tags.RegionOneTagKey", "RegionOneTagValue"),
				),
			},
			{
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			{
				ResourceName:            replicaResource1,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(replicaResource1, "id"),
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
}

func TestCckmAWSKeyMultiRegionLocal(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
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
					key_id 				= %s
					import_key_material = true
					valid_to              = "%s"
				}
			}`
	cmKeyResource := "ciphertrust_cm_key.cm_key"
	awsKeyResource := "ciphertrust_aws_key.multi_region_key"
	replicaResource := "ciphertrust_aws_key.replica"
	createConfigStr := awsConnectionResource + createConfig
	validTo := time.Now().UTC().AddDate(0, 0, 1).Format(time.RFC3339)
	replicateConfigStr := awsConnectionResource + fmt.Sprintf(replicateConfig, "ciphertrust_aws_key.multi_region_key.key_id", validTo)
	modifyPlanConfigStr := awsConnectionResource + fmt.Sprintf(replicateConfig, `"tf-fake-key-id"`, validTo)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
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
			{
				// Re-apply to allow state to settle before import. The Check confirms
				// stable attributes for both resources so ImportStateVerify has
				// known-good values to compare against.
				Config: replicateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(awsKeyResource, "local_key_id", cmKeyResource, "id"),
					resource.TestCheckResourceAttrPair(awsKeyResource, "local_key_name", cmKeyResource, "name"),
					resource.TestCheckResourceAttr(awsKeyResource, "multi_region", "true"),
					resource.TestCheckResourceAttr(awsKeyResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttrSet(awsKeyResource, "id"),
					resource.TestCheckResourceAttrSet(awsKeyResource, "key_id"),
					resource.TestCheckResourceAttrPair(replicaResource, "local_key_id", cmKeyResource, "id"),
					resource.TestCheckResourceAttrPair(replicaResource, "local_key_name", cmKeyResource, "name"),
					resource.TestCheckResourceAttr(replicaResource, "expiration_model", "KEY_MATERIAL_EXPIRES"),
					resource.TestCheckResourceAttr(replicaResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttrSet(replicaResource, "key_id"),
				),
			},
			{
				// Verify ModifyPlan fires an error when replicate_key.key_id is changed.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				ResourceName:            awsKeyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(awsKeyResource, "id"),
			},
			{
				ResourceName:            replicaResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(replicaResource, "id"),
			},
		},
	})
}

func TestCckmAWSKeyRotationNative(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	nativeKey := `
		resource "ciphertrust_aws_key" "native_key" {
			alias        = [local.alias, "%s"]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
			description  = "create description"
			key_usage    = "ENCRYPT_DECRYPT"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
            origin       = "AWS_KMS"
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
		PreCheck:                 func() { cleanupCckmAwsKMS() },
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
}

func TestCckmAWSKeyNativeImport(t *testing.T) {
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
			end_date = "2050-03-07T14:24:00Z"
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
            origin       = "AWS_KMS"
			tags = {
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}
		}`

	aliasList := []string{
		awsKeyNamePrefix + uuid.New().String(),
		awsKeyNamePrefix + uuid.New().String(),
	}
	keyResource := "ciphertrust_aws_key.native_key"
	schedulerOneName := "tf-" + uuid.NewString()[:8]
	createKeyConfigStr := fmt.Sprintf(createKeyConfig, schedulerOneName, aliasList[0], aliasList[1], awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1])
	createKeyConfigStr = applyCDSPAAS(createKeyConfigStr)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Verify the created resource state before import so that the subsequent
				// ImportStateVerify comparison checks against known-correct values,
				// not just whatever Read() happened to return unchecked.
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
					resource.TestCheckResourceAttr(keyResource, "origin", "AWS_KMS"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttrSet(keyResource, "policy"),
					resource.TestCheckResourceAttr(keyResource, "tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "tags.TagKey2", "TagValue2"),
					testCheckAttributeContains(keyResource, "policy", append(awsKeyUsers, awsKeyRoles...), true),
				),
			},
			{
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
			ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
		},
	})
}

// getResourceAttr returns an ImportStateIdFunc (and general state-extraction helper)
// that reads the named attribute from resourceName in the current Terraform state.
// Pass attrName = "id" to get the primary resource ID, or any other attribute name
// (e.g. "key_id", "kms") to extract a different field.
func getResourceAttr(resourceName, attrName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		val, ok := rs.Primary.Attributes[attrName]
		if !ok {
			return "", fmt.Errorf("attribute %q not found in state for %s", attrName, resourceName)
		}
		return val, nil
	}
}

// TestCckmAWSKeyImportMaterialResourceNoExpiry tests the ciphertrust_aws_key_import_material
// resource by re-importing key material without expiry to a key created via ciphertrust_aws_key.
// Note: TestCckmAWSKeyImportKeyMaterialLocal tests the import_key_material block inside
// ciphertrust_aws_key - a different code path.
func TestCckmAWSKeyImportMaterialResourceNoExpiry(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	importConfig := `
		resource "ciphertrust_aws_key" "base" {
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration  = false
			}
			kms    = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
		}
		resource "ciphertrust_aws_key_import_material" "reimport" {
			key_id = %s
			import_key_material {
				source_key_identifier = ciphertrust_aws_key.base.local_key_name
				source_key_tier       = "local"
				key_expiration        = false
			}
		}`

	baseKeyResource := "ciphertrust_aws_key.base"
	reimportResource := "ciphertrust_aws_key_import_material.reimport"
	cmKeyName := "tf-aes-" + uuid.NewString()
	importConfigStr := awsConnectionResource + fmt.Sprintf(importConfig, cmKeyName, "ciphertrust_aws_key.base.key_id")
	modifyPlanConfigStr := awsConnectionResource + fmt.Sprintf(importConfig, cmKeyName, `"tf-fake-key-id"`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: importConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(baseKeyResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(baseKeyResource, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(baseKeyResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(baseKeyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(reimportResource, "id"),
					resource.TestCheckResourceAttrSet(reimportResource, "key_id"),
					resource.TestCheckResourceAttr(reimportResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(reimportResource, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(reimportResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(reimportResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(reimportResource, "expiration_model", "KEY_MATERIAL_DOES_NOT_EXPIRE"),
					resource.TestCheckResourceAttr(reimportResource, "valid_to", ""),
				),
			},
			{
				// Verify ModifyPlan fires an error when import_key_material.key_id is changed.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
		},
	})
}

// TestCckmAWSKeyImportMaterialResourceWithExpiry tests the
// ciphertrust_aws_key_import_material resource with key_expiration = true.
// The re-import sets an expiry date on the key material.
func TestCckmAWSKeyImportMaterialResourceWithExpiry(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	importConfig := `
		resource "ciphertrust_aws_key" "base" {
			import_key_material {
				source_key_name = "%s"
				source_key_tier = "local"
				key_expiration  = false
			}
			kms    = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			customer_master_key_spec = "SYMMETRIC_DEFAULT"
		}
		resource "ciphertrust_aws_key_import_material" "reimport" {
			key_id = ciphertrust_aws_key.base.key_id
			import_key_material {
				source_key_identifier = ciphertrust_aws_key.base.local_key_name
				source_key_tier       = "local"
				key_expiration        = true
				valid_to              = "%s"
			}
		}`

	reimportResource := "ciphertrust_aws_key_import_material.reimport"
	cmKeyName := "tf-aes-" + uuid.NewString()
	validTo := time.Now().UTC().AddDate(0, 0, 1).Format(time.RFC3339)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + fmt.Sprintf(importConfig, cmKeyName, validTo),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(reimportResource, "id"),
					resource.TestCheckResourceAttrSet(reimportResource, "key_id"),
					resource.TestCheckResourceAttr(reimportResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(reimportResource, "key_material_origin", "cckm"),
					resource.TestCheckResourceAttr(reimportResource, "origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(reimportResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(reimportResource, "expiration_model", "KEY_MATERIAL_EXPIRES"),
				testCheckAttributeContains(reimportResource, "valid_to", []string{validTo[:10]}, true),
				),
			},
		},
	})
}

// TestCckmAWSKeyKmsDeleteRecovery verifies provider recovery after a KMS is
// deleted out-of-band. On refresh the KMS and ACL are dropped from state;
// the key is preserved in state (KMS 404 is a hard error for the key). On
// the next apply Terraform recreates the KMS and ACL; the key is
// re-associated with the new KMS registration. The ACL check in Step 3
// confirms the ACL is recreated on the new KMS.
func TestCckmAWSKeyKmsDeleteRecovery(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	keyConfig := `
		resource "ciphertrust_user" "acl_user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.acl_user.id
			actions = ["keycreate"]
		}
		resource "ciphertrust_aws_key" "native_key" {
			alias   = [local.alias]
			kms     = ciphertrust_aws_kms.kms.id
			region  = ciphertrust_aws_kms.kms.regions[0]
			origin  = "AWS_KMS"
		}`
	userName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_aws_key.native_key"
	aclResource := "ciphertrust_aws_acl.user_acl"
	kmsResource := "ciphertrust_aws_kms.kms"
	fullConfig := awsConnectionResource + fmt.Sprintf(keyConfig, userName)

	var capturedKMSID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create KMS + key + user ACL; capture the KMS ID for
				// out-of-band deletion.
				Config: fullConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "key_id"),
					resource.TestCheckResourceAttrSet(aclResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[kmsResource]
						if !ok {
							return fmt.Errorf("kms resource not found in state")
						}
						capturedKMSID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: delete the KMS out-of-band in PreConfig, then refresh state.
				// Expected outcome:
				//   - KMS: dropped from state (404 = warning + RemoveResource).
				//   - Key: preserved in state (KMS 404 is a hard error for the key,
				//     keeping it in state so it can be re-associated when the KMS returns).
				//   - ACL: dropped from state (KMS 404 = warning + RemoveResource, since
				//     an ACL cannot exist without its parent KMS).
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"delete-kms-recovery-test",
						common.URL_AWS_KMS+"/"+capturedKMSID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: re-apply to recover.
				//   - KMS: recreated by Terraform (was in config, absent from state).
				//   - Key: re-associated with the new KMS (was preserved in state in Step 2).
				//   - ACL: recreated from scratch (was removed from state in Step 2).
				Config: fullConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(kmsResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "key_id"),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(aclResource, "id"),
				),
			},
			{
				// Step 4: refresh state so the KMS Read picks up the ACL that was
				// created after the KMS in Step 3. The acls.# check confirms the
				// ACL is visible on the KMS registration.
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResource, "acls.#", "1"),
				),
			},
		},
	})
}
