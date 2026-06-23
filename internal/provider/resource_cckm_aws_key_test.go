package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

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
	"aws_param.next_rotation_date",
	"aws_param.tags",
	"enable_rotation",
	"key_policy",
	"kms_id",
	"labels",
	"multi_region_configuration.multi_region_key_type",
	"multi_region_configuration.primary_key.arn",
	"multi_region_configuration.primary_key.region",
	"multi_region_configuration.replica_keys.#",
	"replicate_key",
	"schedule_for_deletion_days",
	"updated_at",
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
			connection_id = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			connection_id  = ciphertrust_aws_connection.aws_connection.id
			name           = "%s"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[0],
				data.ciphertrust_aws_account_details.account_details.regions[1],
				data.ciphertrust_aws_account_details.account_details.regions[2],
				data.ciphertrust_aws_account_details.account_details.regions[3],
				data.ciphertrust_aws_account_details.account_details.regions[5],
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
			cckm_key_rotation_params = {
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
			aws_param = {
				alias                    = [local.alias, "%s", "%s"]
				auto_rotation_period_in_days = 256
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description              = "create description"
				key_usage                = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate  = true
			enable_key   = true
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler.id
				key_source    = "ciphertrust"
			}
			key_policy = {
				key_admins  = ["%s"]
				key_users   = ["%s"]
				key_admins_roles  = ["%s"]
				key_users_roles   = ["%s"]
			}
			kms_id       = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}`
	updateKeyConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params = {
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
			cckm_key_rotation_params = {
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
			aws_param = {
				alias                    = [local.alias]
				auto_rotation_period_in_days = 128
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description              = "update description"
				key_usage                = "ENCRYPT_DECRYPT"
				tags = {
					TagKey3 = "TagValue3"
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate = true
			enable_key   = false
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_two.id
				key_source    = "ciphertrust"
			}
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
			kms_id    = ciphertrust_aws_kms.kms.id
			region    = ciphertrust_aws_kms.kms.regions[0]
		}`
	updateKeyConfig2 := `
		variable "policy" {
			type    = string
			default = <<-EOT
					{"Version":"2012-10-17","Id":"kms-tf-1","Statement":[{"Sid":"Enable IAM User Permissions 1","Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*"}]}
			EOT
		}
		resource "ciphertrust_aws_policy_template" "policy_template" {
			kms_id = ciphertrust_aws_kms.kms.id
			name   = "%s"
			policy = var.policy
		}
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias        = [local.alias]
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description  = "create description"
				key_usage    = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate  = false
			enable_key   = true
			key_policy = {
				policy_template = ciphertrust_aws_policy_template.policy_template.id
			}
			kms_id       = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}`
	updateKeyConfig3 := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias        = [local.alias]
				customer_master_key_spec = "%s"
				description  = "create description"
				key_usage    = "ENCRYPT_DECRYPT"
				tags         = {}
			}
			auto_rotate  = false
			enable_key   = false
			kms_id       = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
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
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "ciphertrust"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days", createKeyRotationPeriodInDays),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
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
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttrPair(keyResource, "labels.job_config_id", schedulerTwoResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days", updateKeyRotationPeriodInDays),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "update description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Disabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "3"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey3", "TagValue3"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				Config: awsConnectionResource + createKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "ciphertrust"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days", createKeyRotationPeriodInDays),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
				),
			},
			{
				Config: awsConnectionResource + updateKeyConfigStr2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckNoResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					//resource.TestCheckResourceAttrPair(keyResource, "tags.cckm_policy_template_id", policyTemplateResource, "id"),
					// policy not always updated in time
					// testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				Config: awsConnectionResource + updateKeyConfig3Str,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckNoResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Disabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "0"),
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

// Sarah this test seeems superflous
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
			cckm_key_rotation_params = {
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
			aws_param = {
				alias                    = [local.alias, "%s", "%s"]
				auto_rotation_period_in_days = 256
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description              = "create description"
				key_usage                = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate  = true
			enable_key   = true
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler.id
				key_source    = "ciphertrust"
			}
			key_policy = {
				key_admins       = ["%s"]
				key_users        = ["%s"]
				key_admins_roles = ["%s"]
				key_users_roles  = ["%s"]
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
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
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "ciphertrust"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days", "256"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.origin", "AWS_KMS"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
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
// (e.g. "alias", "kms") to extract a different field.
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
			aws_param = {
				alias = [local.alias]
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
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
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
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

// TestCckmAWSNativeKeyMinimalConfig verifies that a resource configuration
// containing only the minimal required attributes is accepted and applied
// without error.
func TestCckmAWSNativeKeyMinimalConfig(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	nativeKeyConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias        = [local.alias]
			}
			kms_id       = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_policy_template" "policy_template" {
            kms_id = ciphertrust_aws_kms.kms.id
			name   = "%s"
			policy = <<-EOT
				%s
			EOT
		}
		resource "ciphertrust_groups" "acl_group" {
			name = "%s"
		}
		resource "ciphertrust_aws_acl" "acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			group   = ciphertrust_groups.acl_group.id
			actions = ["view"]
		}
`

	keyConfigStr := fmt.Sprintf(nativeKeyConfig, "tf-"+uuid.NewString()[:8], defaultPolicy, "tf-"+uuid.NewString()[:8])
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + keyConfigStr,
			},
			{
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMultiRegionNative creates a key and a replica and makes the replica primary
func TestCckmAWSKeyMultiRegionNativeAndMakePrimary(t *testing.T) {
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
				aws_param = {
					alias                    = ["%s", "%s"]
					customer_master_key_spec = "RSA_2048"
					key_usage                = "SIGN_VERIFY"
					multi_region             = true
					tags = {
						CreateTagKey1 = "CreateTagValue1"
						CreateTagKey2 = "CreateTagValue2"
					}
				}
				kms_id = ciphertrust_aws_kms.kms.id
				region = ciphertrust_aws_kms.kms.regions[0]
			}
			resource "ciphertrust_aws_key" "replica"{
				depends_on = [
					ciphertrust_aws_key.multi_region_key,
				]
				aws_param = {
					alias       = ["%s"]
					description = "replica one"
					tags = {
						RegionOneTagKey = "RegionOneTagValue"
					}
				}
				key_policy = {
					key_admins        = ["%s"]
					key_users         = ["%s"]
					key_admins_roles  = ["%s"]
					key_users_roles   = ["%s"]
				}
				region = ciphertrust_aws_kms.kms.regions[1]
				replicate_key = {
					key_id       = ciphertrust_aws_key.multi_region_key.id
					make_primary = true
				}
			}`
	updateConfig := `
			resource "ciphertrust_aws_key" "multi_region_key" {
				aws_param = {
					alias                    = ["%s", "%s"]
					customer_master_key_spec = "RSA_2048"
					key_usage                = "SIGN_VERIFY"
					multi_region             = true
					tags = {
						CreateTagKey1 = "CreateTagValue1"
						CreateTagKey2 = "CreateTagValue2"
					}
				}
				kms_id = ciphertrust_aws_kms.kms.id
				region = ciphertrust_aws_kms.kms.regions[0]
			}
			resource "ciphertrust_aws_key" "replica"{
				aws_param = {
					alias       = ["%s"]
					description = "replica one"
					tags = {
						RegionOneTagKey = "RegionOneTagValue"
					}
				}
				key_policy = {
					key_admins        = ["%s"]
					key_users         = ["%s"]
					key_admins_roles  = ["%s"]
					key_users_roles   = ["%s"]
				}
				region         = ciphertrust_aws_kms.kms.regions[1]
				replicate_key = {
					key_id = ciphertrust_aws_key.multi_region_key.id
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
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.replica_keys.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey2", "CreateTagValue2"),

					resource.TestCheckResourceAttrSet(replicaResource1, "id"),
					resource.TestCheckResourceAttr(replicaResource1, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(replicaResource1, "key_users.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(replicaResource1, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(replicaResource1, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(replicaResource1, "multi_region_configuration.replica_keys.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.alias.0", replicaAlias),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.description", "replica one"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource1, "aws_param.policy"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.tags.RegionOneTagKey", "RegionOneTagValue"),
					// Sometimes - this is true
					//resource.TestCheckResourceAttr(replicaResource1, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						replicaResource1,
						tfjsonpath.New("aws_param").AtMapKey("policy"),
						knownvalue.StringRegexp(regexp.MustCompile(awsKeyUsers[0]))),
				},
			},
			{
				// Update state before import as primary region has changed. The Check
				// confirms stable attributes are correct so the subsequent
				// ImportStateVerify steps compare against known-good values.
				Config: createResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey2", "CreateTagValue2"),

					resource.TestCheckResourceAttrSet(replicaResource1, "id"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource1, "aws_param.policy"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.tags.RegionOneTagKey", "RegionOneTagValue"),
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
				// After update: multi_region_key (regions[0]) is now a REPLICA;
				// replica (regions[1]) is now the PRIMARY with one replica key.
				Config: updateResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),

					resource.TestCheckResourceAttr(replicaResource1, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(replicaResource1, "multi_region_configuration.replica_keys.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource1, "aws_param.tags.%", "1"),
				),
			},
		},
	})
}

// TestCckmAWSKeyMultiRegionNative creates a key and a replica and uses primary_region to change replica key to the primary key
// TestCckmAWSKeyMultiRegionNative creates a key and a replica and uses the primary_key to make change the replica to the primary
func TestCckmAWSKeyMultiRegionNativeAndPrimaryRegion(t *testing.T) {
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
			resource "ciphertrust_aws_key" "primary_key" {
				aws_param = {
					alias                    = ["%s", "%s"]
					customer_master_key_spec = "RSA_2048"
					key_usage                = "SIGN_VERIFY"
					multi_region             = true
					tags = {
						CreateTagKey1 = "CreateTagValue1"
						CreateTagKey2 = "CreateTagValue2"
					}
				}
				kms_id = ciphertrust_aws_kms.kms.id
				region = ciphertrust_aws_kms.kms.regions[0]
			}
			resource "ciphertrust_aws_key" "replica"{
				depends_on = [
					ciphertrust_aws_key.primary_key,
				]
				aws_param = {
					alias       = ["%s"]
					description = "replica one"
					tags = {
						RegionOneTagKey = "RegionOneTagValue"
					}
				}
				key_policy = {
					key_admins        = ["%s"]
					key_users         = ["%s"]
					key_admins_roles  = ["%s"]
					key_users_roles   = ["%s"]
				}
				region = ciphertrust_aws_kms.kms.regions[1]
				replicate_key = {
					key_id       = ciphertrust_aws_key.primary_key.id
				}
			}`
	updateConfig := `
			resource "ciphertrust_aws_key" "primary_key" {
				aws_param = {
					alias                    = ["%s", "%s"]
					customer_master_key_spec = "RSA_2048"
					key_usage                = "SIGN_VERIFY"
					multi_region             = true
					tags = {
						CreateTagKey1 = "CreateTagValue1"
						CreateTagKey2 = "CreateTagValue2"
					}
				}
				kms_id = ciphertrust_aws_kms.kms.id
				region = ciphertrust_aws_kms.kms.regions[0]
				primary_region = ciphertrust_aws_kms.kms.regions[1]
			}
			resource "ciphertrust_aws_key" "replica"{
				aws_param = {
					alias       = ["%s"]
					description = "replica one"
					tags = {
						RegionOneTagKey = "RegionOneTagValue"
					}
				}
				key_policy = {
					key_admins        = ["%s"]
					key_users         = ["%s"]
					key_admins_roles  = ["%s"]
					key_users_roles   = ["%s"]
				}
				region         = ciphertrust_aws_kms.kms.regions[1]
				replicate_key = {
					key_id = ciphertrust_aws_key.primary_key.id
				}
			}`
	aliasA := awsKeyNamePrefix + uuid.New().String()[8:]
	aliasB := awsKeyNamePrefix + uuid.New().String()[8:]
	replicaAlias := awsKeyNamePrefix + uuid.New().String()[8:]
	keyResource := "ciphertrust_aws_key.primary_key"
	replicaResource := "ciphertrust_aws_key.replica"
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
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey2", "CreateTagValue2"),

					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(replicaResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(replicaResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(replicaResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(replicaResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.0", replicaAlias),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.description", "replica one"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.RegionOneTagKey", "RegionOneTagValue"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						replicaResource,
						tfjsonpath.New("aws_param").AtMapKey("policy"),
						knownvalue.StringRegexp(regexp.MustCompile(awsKeyUsers[0]))),
				},
			},
			{
				// Update state before import as primary region has changed. The Check
				// confirms stable attributes are correct so the subsequent
				// ImportStateVerify steps compare against known-good values.
				Config: createResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey2", "CreateTagValue2"),

					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.RegionOneTagKey", "RegionOneTagValue"),
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
				ResourceName:            replicaResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(replicaResource, "id"),
			},
			{
				// After update: the primary key will no longer be the primary
				// A refresh is required to update the state of the replica
				Config: updateResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.%", "1"),
				),
			},
			{
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
				),
			},
		},
	})
}
