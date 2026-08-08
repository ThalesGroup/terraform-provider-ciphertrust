package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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
	// Lab / CI CMs present self-signed certs (often without IP SANs). Honour
	// CIPHERTRUST_CA_CERT when set; otherwise opt into skip-verify so the
	// inline test provider block isn't blocked by the secure-by-default TLS
	// behaviour introduced for end users.
	tlsLine := "  no_ssl_verify = true"
	if caCert := os.Getenv("CIPHERTRUST_CA_CERT"); caCert != "" {
		tlsLine = fmt.Sprintf("  ca_cert = %q", caCert)
	}
	awsConfig := `
		provider "ciphertrust" {
			aws_operation_timeout = %d
` + tlsLine + `
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

// TestCckmAWSKeyNative tests creating native keys and update functionality.
// The test exercises a plain create followed by a series of updates that toggle
// auto-rotation, the rotation scheduler, aliases, key enable/disable, tags, and
// key policy. Post-create-only attributes (auto_rotate, enable_rotation, >1 alias)
// are NOT present in the initial create config; they are added in the first update.
func TestCckmAWSKeyNative(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// createKeyConfig is a minimal create: 1 alias, no auto_rotate, no enable_rotation.
	// Post-create attributes are applied in the first update (addPostCreateConfig).
	createKeyConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias                    = [local.alias]
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description              = "create description"
				key_usage                = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			enable_key = true
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`

	// addPostCreateConfig is the first update: adds 2 more aliases, enables auto-rotation,
	// and attaches a rotation scheduler. These are the attributes that cannot be set at create.
	addPostCreateConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params = {
				cloud_name = "aws"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias                        = [local.alias, "%s", "%s"]
				auto_rotation_period_in_days = 256
				customer_master_key_spec     = "SYMMETRIC_DEFAULT"
				description                  = "create description"
				key_usage                    = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate = true
			enable_key  = true
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler.id
				key_source    = "local"
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`

	updateKeyConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params = {
				cloud_name = "aws"
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
				cloud_name = "aws"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias                        = [local.alias]
				auto_rotation_period_in_days = 128
				customer_master_key_spec     = "SYMMETRIC_DEFAULT"
				description                  = "update description"
				key_usage                    = "ENCRYPT_DECRYPT"
				tags = {
					TagKey3 = "TagValue3"
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate = true
			enable_key  = false
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_two.id
				key_source    = "local"
			}
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
			kms_id                     = ciphertrust_aws_kms.kms.id
			region                     = ciphertrust_aws_kms.kms.regions[0]
			schedule_for_deletion_days = 13
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
				alias                    = [local.alias]
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description              = "create description"
				key_usage                = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate = false
			enable_key  = true
			key_policy = {
				policy_template = ciphertrust_aws_policy_template.policy_template.id
			}
			kms_id                     = ciphertrust_aws_kms.kms.id
			region                     = ciphertrust_aws_kms.kms.regions[0]
			schedule_for_deletion_days = 20
		}`
	updateKeyConfig3 := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias                    = [local.alias]
				customer_master_key_spec = "%s"
				description              = "create description"
				key_usage                = "ENCRYPT_DECRYPT"
				tags                     = {}
			}
			auto_rotate                = false
			enable_key                 = false
			kms_id                     = ciphertrust_aws_kms.kms.id
			region                     = ciphertrust_aws_kms.kms.regions[0]
			schedule_for_deletion_days = 8
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

	createKeyRotationPeriodInDays := "256"
	updateKeyRotationPeriodInDays := "128"

	createKeyConfigStr := createKeyConfig
	addPostCreateConfigStr := fmt.Sprintf(addPostCreateConfig, schedulerOneName, aliasList[0], aliasList[1])
	addPostCreateConfigStr = applyCDSPAAS(addPostCreateConfigStr)
	updateKeyConfigStr := fmt.Sprintf(updateKeyConfig, schedulerOneName, schedulerTwoName, awsKeyPolicy)
	updateKeyConfigStr = applyCDSPAAS(updateKeyConfigStr)
	updateKeyConfigStr2 := fmt.Sprintf(updateKeyConfig2, policyTemplateName)
	updateKeyConfig3Str := fmt.Sprintf(updateKeyConfig3, "SYMMETRIC_DEFAULT")
	modifyPlanConfigStr := fmt.Sprintf(updateKeyConfig3, "RSA_2048")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: plain create - minimal config, no post-create attributes.
			{
				Config: awsConnectionResource + createKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
				),
			},
			// Step 2: import state verify.
			{
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			// Step 3: first update - add 2 more aliases, enable auto-rotation, attach scheduler.
			{
				Config: awsConnectionResource + addPostCreateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days", createKeyRotationPeriodInDays),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "local"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
				),
			},
			// Step 4: second update - change scheduler, reduce to 1 alias, disable key, change policy.
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
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "13"),
				),
			},
			// Step 5: third update - re-apply addPostCreateConfig (re-enable, 3 aliases, scheduler 1).
			{
				Config: awsConnectionResource + addPostCreateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "local"),
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
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "13"),
				),
			},
			// Step 6: fourth update - remove rotation scheduler, disable auto_rotate, policy template.
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
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "20"),
				),
			},
			// Step 7: fifth update - clear tags, disable key.
			{
				Config: awsConnectionResource + updateKeyConfig3Str,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckNoResourceAttr(keyResource, "aws_param.auto_rotation_period_in_days"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Disabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "8"),
				),
			},
			// Step 8: verify ModifyPlan fires an error when customer_master_key_spec is changed.
			{
				Config:      awsConnectionResource + modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
		},
	})
}

// TestCckmAWSKeyNativeCreateRejections verifies that ModifyPlan rejects each of the four
// attributes that cannot be set during key creation: multiple aliases, auto_rotate=true,
// enable_rotation, and enable_key=false. Each step is plan-only; no infrastructure is created.
func TestCckmAWSKeyNativeCreateRejections(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	multipleAliasesConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias = [local.alias, "tf-aws-second-alias"]
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`

	autoRotateConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			auto_rotate = true
			kms_id      = ciphertrust_aws_kms.kms.id
			region      = ciphertrust_aws_kms.kms.regions[0]
		}`

	enableRotationConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params = {
				cloud_name = "aws"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_aws_key" "native_key" {
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler.id
				key_source    = "local"
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`

	disabledKeyConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			enable_key = false
			kms_id     = ciphertrust_aws_kms.kms.id
			region     = ciphertrust_aws_kms.kms.regions[0]
		}`

	schedulerName := "tf-" + uuid.NewString()[:8]
	enableRotationConfigStr := fmt.Sprintf(enableRotationConfig, schedulerName)
	enableRotationConfigStr = applyCDSPAAS(enableRotationConfigStr)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      awsConnectionResource + multipleAliasesConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Additional aliases cannot be set during key creation`),
			},
			{
				Config:      awsConnectionResource + autoRotateConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Auto-rotation cannot be enabled during key creation`),
			},
			{
				Config:      awsConnectionResource + enableRotationConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Rotation scheduler cannot be configured during key creation`),
			},
			{
				Config:      awsConnectionResource + disabledKeyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Key cannot be disabled during key creation`),
			},
		},
	})
}

// TestCckmAWSKeyNativeImport verifies that a key created and updated with minimal
// config can be successfully imported.
func TestCckmAWSKeyNativeImport(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// Step 1: minimal create (no post-create attributes).
	createKeyConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias                    = [local.alias]
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description              = "create description"
				key_usage                = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			enable_key = true
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`

	// Step 2: first update - adds 2 more aliases, auto-rotation, and scheduler.
	// This is the config that will be in place when ImportState runs.
	fullKeyConfig := `
		resource "ciphertrust_scheduler" "scheduler" {
			cckm_key_rotation_params = {
				cloud_name = "aws"
			}
			end_date   = "2050-03-07T14:24:00Z"
			name       = "%s"
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias                        = [local.alias, "%s", "%s"]
				auto_rotation_period_in_days = 256
				customer_master_key_spec     = "SYMMETRIC_DEFAULT"
				description                  = "create description"
				key_usage                    = "ENCRYPT_DECRYPT"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			auto_rotate = true
			enable_key  = true
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler.id
				key_source    = "local"
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
	createKeyConfigStr := createKeyConfig
	fullKeyConfigStr := fmt.Sprintf(fullKeyConfig, schedulerOneName, aliasList[0], aliasList[1])
	fullKeyConfigStr = applyCDSPAAS(fullKeyConfigStr)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: plain create.
			{
				Config: awsConnectionResource + createKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
				),
			},
			// Step 2: update to full configuration - add aliases, auto-rotation, scheduler.
			{
				Config: awsConnectionResource + fullKeyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "auto_rotate", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "local"),
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
				),
			},
			// Step 3: import state verify.
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

// TestCckmAWSKeyPolicyUpdates verifies switching a key between the structured
// key_admins/key_users policy form and the raw policy JSON form, and back again.
// Requires AWS_KEY_USERS (2 comma-separated user suffixes) and AWS_KEY_ROLES
// (2 comma-separated role suffixes) to be set.
func TestCckmAWSKeyPolicyUpdates(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	awsKeyUsers := getAwsUsers()
	if len(awsKeyUsers) != 2 {
		t.Skip("AWS_KEY_USERS is not exported or doesn't contain 2 users")
	}
	awsKeyRoles := getAwsRoles()
	if len(awsKeyRoles) != 2 {
		t.Skip("AWS_KEY_ROLES is not exported or doesn't contain 2 roles")
	}

	// structuredPolicyConfig uses the key_admins / key_users / key_admins_roles /
	// key_users_roles fields to build the KMS key policy. The key is multi-region
	// and a replica (no key_policy) is created in regions[1] to verify that
	// policy updates on the primary do not affect replication.
	structuredPolicyConfig := `
		resource "ciphertrust_aws_key" "policy_key" {
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
			key_policy = {
				key_admins       = ["%s"]
				key_users        = ["%s"]
				key_admins_roles = ["%s"]
				key_users_roles  = ["%s"]
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_key" "replica_key" {
			depends_on = [ciphertrust_aws_key.policy_key]
			aws_param = {
				alias = ["%s"]
			}
			region = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id = ciphertrust_aws_key.policy_key.id
			}
		}`

	// rawPolicyConfig replaces the structured fields with an inline raw JSON policy.
	rawPolicyConfig := `
		resource "ciphertrust_aws_key" "policy_key" {
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_key" "replica_key" {
			aws_param = {
				alias = ["%s"]
			}
			region = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id = ciphertrust_aws_key.policy_key.id
			}
		}`

	keyResource := "ciphertrust_aws_key.policy_key"
	replicaResource := "ciphertrust_aws_key.replica_key"
	replicaAlias := awsKeyNamePrefix + uuid.New().String()[8:]

	step1Config := fmt.Sprintf(structuredPolicyConfig,
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1], replicaAlias)
	step2Config := fmt.Sprintf(rawPolicyConfig, awsKeyPolicy, replicaAlias)
	step3Config := fmt.Sprintf(structuredPolicyConfig,
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1], replicaAlias)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with structured key_admins/key_users policy.
			{
				Config: awsConnectionResource + step1Config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource, "aws_param.policy"),
				),
			},
			// Step 2: update to raw JSON policy - users/roles should no longer appear.
			{
				Config: awsConnectionResource + step2Config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
				),
			},
			// Step 3: update back to structured key_admins/key_users policy.
			{
				Config: awsConnectionResource + step3Config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
				),
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

// TestCckmAWSKeyMultiRegionNative creates a key and a replica and makes the replica primary
func TestCckmAWSKeyMultiRegionNativeAndMakePrimary(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createConfig := `
			resource "ciphertrust_aws_key" "multi_region_key" {
				aws_param = {
					alias                    = ["%s"]
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
	createResources := awsConnectionResource + fmt.Sprintf(createConfig, aliasA, replicaAlias)
	updateResources := awsConnectionResource + fmt.Sprintf(updateConfig, aliasA, aliasB, replicaAlias)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.replica_keys.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey2", "CreateTagValue2"),

					resource.TestCheckResourceAttrSet(replicaResource1, "id"),
					resource.TestCheckResourceAttr(replicaResource1, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(replicaResource1, "key_users.#", "0"),
					resource.TestCheckResourceAttr(replicaResource1, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttr(replicaResource1, "key_users_roles.#", "0"),
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
			},
			{
				// Update state before import as primary region has changed. The Check
				// confirms stable attributes are correct so the subsequent
				// ImportStateVerify steps compare against known-good values.
				Config: createResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
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
	createConfig := `
			resource "ciphertrust_aws_key" "primary_key" {
				aws_param = {
					alias                    = ["%s"]
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
			resource "ciphertrust_aws_key" "replica" {
				aws_param = {
					alias       = ["%s"]
					description = "replica one"
					tags = {
						RegionOneTagKey = "RegionOneTagValue"
					}
				}
				region = ciphertrust_aws_kms.kms.regions[1]
				replicate_key = {
					key_id = ciphertrust_aws_key.primary_key.id
				}
			}
			resource "ciphertrust_aws_key" "replica2" {
				aws_param = {
					alias = ["%s"]
					tags = {
						RegionTwoTagKey = "RegionTwoTagValue"
					}
				}
				region = ciphertrust_aws_kms.kms.regions[2]
				replicate_key = {
					key_id = ciphertrust_aws_key.primary_key.id
				}
			}
			resource "ciphertrust_aws_key" "replica3" {
				aws_param = {
					alias = ["%s"]
					tags = {
						RegionThreeTagKey = "RegionThreeTagValue"
					}
				}
				region = ciphertrust_aws_kms.kms.regions[3]
				replicate_key = {
					key_id = ciphertrust_aws_key.primary_key.id
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
			resource "ciphertrust_aws_key" "replica" {
				aws_param = {
					alias       = ["%s"]
					description = "replica one"
					tags = {
						RegionOneTagKey = "RegionOneTagValue"
					}
				}
				region = ciphertrust_aws_kms.kms.regions[1]
				replicate_key = {
					key_id = ciphertrust_aws_key.primary_key.id
				}
			}
			resource "ciphertrust_aws_key" "replica2" {
				aws_param = {
					alias = ["%s"]
					tags = {
						RegionTwoTagKey = "RegionTwoTagValue"
					}
				}
				region = ciphertrust_aws_kms.kms.regions[2]
				replicate_key = {
					key_id = ciphertrust_aws_key.primary_key.id
				}
			}
			resource "ciphertrust_aws_key" "replica3" {
				aws_param = {
					alias = ["%s"]
					tags = {
						RegionThreeTagKey = "RegionThreeTagValue"
					}
				}
				region = ciphertrust_aws_kms.kms.regions[3]
				replicate_key = {
					key_id = ciphertrust_aws_key.primary_key.id
				}
			}`
	aliasA := "tf" + uuid.New().String()[8:]
	aliasB := "tf" + uuid.New().String()[8:]
	replicaAlias := "tf" + uuid.New().String()[8:]
	replica2Alias := "tf" + uuid.New().String()[8:]
	replica3Alias := "tf" + uuid.New().String()[8:]
	keyResource := "ciphertrust_aws_key.primary_key"
	replicaResource := "ciphertrust_aws_key.replica"
	replica2Resource := "ciphertrust_aws_key.replica2"
	replica3Resource := "ciphertrust_aws_key.replica3"
	createResources := awsConnectionResource + fmt.Sprintf(createConfig, aliasA, replicaAlias, replica2Alias, replica3Alias)
	updateResources := awsConnectionResource + fmt.Sprintf(updateConfig, aliasA, aliasB, replicaAlias, replica2Alias, replica3Alias)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the primary and all three replicas in one apply.
				// replica_keys.# on the primary is not checked here because the primary
				// is read before the replicas exist; the count is verified in Step 2.
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    createResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey2", "CreateTagValue2"),
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),

					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(replicaResource, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(replicaResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(replicaResource, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttr(replicaResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.0", replicaAlias),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.description", "replica one"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.RegionOneTagKey", "RegionOneTagValue"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),

					resource.TestCheckResourceAttrSet(replica2Resource, "id"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.alias.0", replica2Alias),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replica2Resource, "aws_param.policy"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.tags.RegionTwoTagKey", "RegionTwoTagValue"),
					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),

					resource.TestCheckResourceAttrSet(replica3Resource, "id"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.alias.0", replica3Alias),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replica3Resource, "aws_param.policy"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.tags.RegionThreeTagKey", "RegionThreeTagValue"),
					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
				),
			},
			{
				// Step 2: refresh state so all keys are re-read.
				// Verify the full multi_region_configuration for all 4 keys including replica_keys.#=3.
				PreConfig:    func() { logTestStep(t.Name(), "Step 2") },
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey1", "CreateTagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.CreateTagKey2", "CreateTagValue2"),

					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replicaResource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replicaResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.RegionOneTagKey", "RegionOneTagValue"),

					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replica2Resource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.multi_region", "true"),

					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replica3Resource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.multi_region", "true"),
				),
			},
			{
				PreConfig:               func() { logTestStep(t.Name(), "Step 3") },
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			{
				PreConfig:               func() { logTestStep(t.Name(), "Step 4") },
				ResourceName:            replicaResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(replicaResource, "id"),
			},
			{
				PreConfig:               func() { logTestStep(t.Name(), "Step 5") },
				ResourceName:            replica2Resource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(replica2Resource, "id"),
			},
			{
				PreConfig:               func() { logTestStep(t.Name(), "Step 6") },
				ResourceName:            replica3Resource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsKey,
				ImportStateIdFunc:       getResourceAttr(replica3Resource, "id"),
			},
			{
				// Step 7: promote replica (regions[1]) to primary via primary_region.
				// The original primary becomes a REPLICA. A refresh is needed to observe
				// the new primary's updated multi_region_key_type.
				PreConfig: func() { logTestStep(t.Name(), "Step 7") },
				Config:    updateResources,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.multi_region", "true"),
				),
			},
			{
				// Step 8: refresh state to confirm the promoted replica is now PRIMARY.
				// All 4 keys must agree on the new primary's region and ARN, and every key
				// must list all 3 replica regions in replica_keys.
				PreConfig:    func() { logTestStep(t.Name(), "Step 8") },
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(keyResource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(keyResource, "multi_region_configuration.primary_key.arn"),

					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replicaResource, "multi_region_configuration.primary_key.arn"),

					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replica2Resource, "multi_region_configuration.primary_key.arn"),

					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replica3Resource, "multi_region_configuration.primary_key.arn"),

					// All 4 keys must agree on the new primary's region and ARN.
					resource.TestCheckResourceAttrPair(keyResource, "multi_region_configuration.primary_key.region", replicaResource, "multi_region_configuration.primary_key.region"),
					resource.TestCheckResourceAttrPair(replica2Resource, "multi_region_configuration.primary_key.region", replicaResource, "multi_region_configuration.primary_key.region"),
					resource.TestCheckResourceAttrPair(replica3Resource, "multi_region_configuration.primary_key.region", replicaResource, "multi_region_configuration.primary_key.region"),
					resource.TestCheckResourceAttrPair(keyResource, "multi_region_configuration.primary_key.arn", replicaResource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttrPair(replica2Resource, "multi_region_configuration.primary_key.arn", replicaResource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttrPair(replica3Resource, "multi_region_configuration.primary_key.arn", replicaResource, "multi_region_configuration.primary_key.arn"),
				),
			},
		},
	})
}

// TestCckmAWSKeyMultiRegionNativeMultiReplica creates a native multi-region primary key and
// replicates it to three regions in one apply, then verifies the multi-region configuration
// is fully propagated to all keys in the MR set. This exercises waitForReplicaRegionInAllMRKeys
// which ensures the CM background task has updated every existing key before the provider returns.
func TestCckmAWSKeyMultiRegionNativeMultiReplica(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	alias := "tf" + uuid.New().String()[8:]
	replicaAlias := "tf" + uuid.New().String()[8:]
	replica2Alias := "tf" + uuid.New().String()[8:]
	replica3Alias := "tf" + uuid.New().String()[8:]

	createConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_key" "mr_primary" {
			aws_param = {
				alias        = ["%s"]
				multi_region = true
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}
		resource "ciphertrust_aws_key" "mr_replica" {
			aws_param = { alias = ["%s"] }
			region    = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id = ciphertrust_aws_key.mr_primary.id
			}
		}
		resource "ciphertrust_aws_key" "mr_replica2" {
			aws_param = { alias = ["%s"] }
			region    = ciphertrust_aws_kms.kms.regions[2]
			replicate_key = {
				key_id = ciphertrust_aws_key.mr_primary.id
			}
		}
		resource "ciphertrust_aws_key" "mr_replica3" {
			aws_param = { alias = ["%s"] }
			region    = ciphertrust_aws_kms.kms.regions[3]
			replicate_key = {
				key_id = ciphertrust_aws_key.mr_primary.id
			}
		}`, alias, replicaAlias, replica2Alias, replica3Alias)

	primaryResource := "ciphertrust_aws_key.mr_primary"
	replicaResource := "ciphertrust_aws_key.mr_replica"
	replica2Resource := "ciphertrust_aws_key.mr_replica2"
	replica3Resource := "ciphertrust_aws_key.mr_replica3"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the primary and all three replicas in one apply.
				// waitForReplicaRegionInAllMRKeys ensures the CM background task has propagated
				// each new replica region to all existing keys before returning. The primary and
				// prior replicas should therefore already show the correct replica_keys.# count.
				// replica3 is the last to be created and is excluded from its own wait, so its
				// replica_keys.# is checked in Step 2 (RefreshState) rather than here.
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(primaryResource, "id"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replicaResource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttrSet(replica2Resource, "id"),
					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replica2Resource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttrSet(replica3Resource, "id"),
					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.key_state", "Enabled"),
				),
			},
			{
				// Step 2: refresh state. All 4 keys must now show replica_keys.#=3 and
				// must all agree on the same primary_key.region and primary_key.arn.
				PreConfig:    func() { logTestStep(t.Name(), "Step 2") },
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.replica_keys.#", "3"),

					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replicaResource, "multi_region_configuration.primary_key.arn"),

					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica2Resource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replica2Resource, "multi_region_configuration.primary_key.arn"),

					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replica3Resource, "multi_region_configuration.replica_keys.#", "3"),
					resource.TestCheckResourceAttrSet(replica3Resource, "multi_region_configuration.primary_key.arn"),

					// All replicas must agree on the same primary_key region and ARN.
					resource.TestCheckResourceAttrPair(replicaResource, "multi_region_configuration.primary_key.region", primaryResource, "region"),
					resource.TestCheckResourceAttrPair(replica2Resource, "multi_region_configuration.primary_key.region", primaryResource, "region"),
					resource.TestCheckResourceAttrPair(replica3Resource, "multi_region_configuration.primary_key.region", primaryResource, "region"),
					resource.TestCheckResourceAttrPair(replicaResource, "multi_region_configuration.primary_key.arn", primaryResource, "aws_param.arn"),
					resource.TestCheckResourceAttrPair(replica2Resource, "multi_region_configuration.primary_key.arn", primaryResource, "aws_param.arn"),
					resource.TestCheckResourceAttrPair(replica3Resource, "multi_region_configuration.primary_key.arn", primaryResource, "aws_param.arn"),
				),
			},
		},
	})
}

// scheduleAwsKeyDeletionOutOfBand schedules an AWS key for deletion outside of Terraform
// by calling the schedule-deletion API directly. Used in tests that verify provider behaviour
// when a key enters PendingDeletion state without Terraform's knowledge.
// Failures are intentionally ignored - the test will catch any unexpected state.
func scheduleAwsKeyDeletionOutOfBand(keyID string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	payload, _ := json.Marshal(map[string]int{"days": 7})
	_, _ = client.PostDataV2(
		context.Background(),
		"oob-schedule-deletion-"+keyID,
		common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion",
		payload,
	)
}

// TestCckmAWSKeyNativePendingDeletionRefresh verifies that when an AWS key is scheduled
// for deletion out-of-band (without Terraform), a subsequent terraform refresh retains
// the resource in state and issues a warning rather than removing it from state.
// AWS automatically disables keys pending deletion, so Terraform will report drift on
// enable_key - ExpectNonEmptyPlan: true captures this expected drift.
func TestCckmAWSKeyNativePendingDeletionRefresh(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	keyConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias = [local.alias]
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`

	keyResource := "ciphertrust_aws_key.native_key"
	var capturedKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a minimal native key and capture the ID for OOB deletion.
				Config: awsConnectionResource + keyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
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
				// in state with key_state = "PendingDeletion". Terraform reports drift on
				// enable_key because AWS automatically disables keys pending deletion.
				PreConfig: func() {
					scheduleAwsKeyDeletionOutOfBand(capturedKeyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					// Use a closure so capturedKeyID is read at execution time (after Step 1
					// has populated it), not at TestCase definition time when it is still "".
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
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "PendingDeletion"),
				),
			},
		},
	})
}

// TestCckmAWSKeyNativePendingDeletionUpdate verifies that when an AWS key is scheduled
// for deletion out-of-band, a subsequent terraform apply that includes a key_policy update
// succeeds with a warning, retains the resource in state, and reflects the updated policy.
// AWS permits key policy updates on keys in PendingDeletion state.
func TestCckmAWSKeyNativePendingDeletionUpdate(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	awsKeyUsers := getAwsUsers()
	if len(awsKeyUsers) != 2 {
		t.Skip("AWS_KEY_USERS is not exported or doesn't contain 2 users")
	}
	awsKeyRoles := getAwsRoles()
	if len(awsKeyRoles) != 2 {
		t.Skip("AWS_KEY_ROLES is not exported or doesn't contain 2 roles")
	}

	createConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias = [local.alias]
			}
			key_policy = {
				key_admins       = ["%s"]
				key_users        = ["%s"]
				key_admins_roles = ["%s"]
				key_users_roles  = ["%s"]
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`,
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1],
	)

	updateConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias = [local.alias]
			}
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}`, awsKeyPolicy)

	keyResource := "ciphertrust_aws_key.native_key"
	var capturedKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a native key with a structured key policy containing
				// admins and users. Capture the ID for OOB deletion in Step 2.
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
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
				// Step 2: schedule the key for deletion out-of-band, then apply a policy update.
				// Expected: Update detects PendingDeletion state, issues a warning (not an error),
				// applies the policy change (AWS permits policy updates on keys pending deletion),
				// and retains the resource in state. The admins/users from the create policy
				// should no longer appear in the updated policy.
				PreConfig: func() {
					scheduleAwsKeyDeletionOutOfBand(capturedKeyID)
				},
				Config: awsConnectionResource + updateConfig,
				Check: resource.ComposeTestCheckFunc(
					// Use a closure so capturedKeyID is read at execution time (after Step 1
					// has populated it), not at TestCase definition time when it is still "".
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
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "PendingDeletion"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
		},
	})
}
