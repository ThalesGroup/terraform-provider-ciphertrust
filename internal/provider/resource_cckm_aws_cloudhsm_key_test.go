package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// importStateVerifyIgnoreAwsCloudHSMKey lists the attributes that cannot round-trip through
// terraform import for unlinked CloudHSM keys. Extra entries are harmless when attributes
// already match.
var importStateVerifyIgnoreAwsCloudHSMKey = []string{
	// aws_param.alias: not applied to AWS for unlinked keys, so not returned by GET.
	"aws_param.alias",
	// aws_param.description: Read() preserves prior state value for unlinked keys; no prior state after import.
	"aws_param.description",
	// aws_param.tags: not applied/returned for unlinked keys (AWS-side operation).
	"aws_param.tags",
	// bypass_policy_lockout_safety_check: write-only input; not returned by GET.
	"bypass_policy_lockout_safety_check",
	// enable_key: not applied for unlinked keys (block/enable ops require linked_state = true).
	"enable_key",
	// enable_rotation: not surfaced in GET response; cannot round-trip.
	"enable_rotation",
	// key_policy: not surfaced in GET response; cannot round-trip.
	"key_policy",
	// schedule_for_deletion_days: null for active keys; does not round-trip cleanly after import.
	"schedule_for_deletion_days",
}

// TestCckmAWSCloudHSMUnlinkedKey tests creating, updating, and importing unlinked CloudHSM keys.
// It requires the following environment variables in addition to the common AWS credentials:
//   - AWS_CLOUDHSM_CLUSTER_ID: the CloudHSM cluster ID to use for the custom key store
//   - AWS_CLOUDHSM_KEY_STORE_PASSWORD: the CloudHSM key store password
//   - AWS_CLOUDHSM_TRUST_ANCHOR_CERT: PEM trust anchor certificate for the CloudHSM cluster
func TestCckmAWSCloudHSMUnlinkedKey(t *testing.T) {
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

	cloudHSMClusterID := os.Getenv("AWS_CLOUDHSM_CLUSTER_ID")
	if cloudHSMClusterID == "" {
		t.Skip("AWS_CLOUDHSM_CLUSTER_ID is not exported")
	}
	keyStorePassword := os.Getenv("AWS_CLOUDHSM_KEY_STORE_PASSWORD")
	if keyStorePassword == "" {
		t.Skip("AWS_CLOUDHSM_KEY_STORE_PASSWORD is not exported")
	}
	trustAnchorCert := os.Getenv("AWS_CLOUDHSM_TRUST_ANCHOR_CERT")
	if trustAnchorCert == "" {
		t.Skip("AWS_CLOUDHSM_TRUST_ANCHOR_CERT is not exported")
	}

	createKeyStoreConfig := `
		resource "ciphertrust_aws_custom_keystore" "unlinked_cloudhsm_keystore" {
			name         = "%s"
			region       = ciphertrust_aws_kms.kms.regions[0]
			kms_id       = ciphertrust_aws_kms.kms.id
			linked_state = false
			aws_param = {
				cloud_hsm_cluster_id      = "%s"
				custom_key_store_type     = "AWS_CLOUDHSM"
				key_store_password        = "%s"
				trust_anchor_certificate  = "%s"
			}
		}`
	keyStoreName := "tf-cloudhsm-ks-" + uuid.New().String()[:8]
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig,
		keyStoreName, cloudHSMClusterID, keyStorePassword, trustAnchorCert)

	createPolicyTemplateConfig := `
		resource "ciphertrust_aws_policy_template" "cloudhsm_template" {
			name             = "%s"
			kms_id           = ciphertrust_aws_kms.kms.id
			key_admins       = ["%s"]
			key_users        = ["%s"]
			key_admins_roles = ["%s"]
			key_users_roles  = ["%s"]
		}`
	policyTemplateConfigStr := fmt.Sprintf(createPolicyTemplateConfig,
		"tf-"+uuid.New().String()[:8],
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1])

	enableRotationName := "tf-cloudhsm-rot-" + uuid.New().String()[:8]
	enableRotationConfig := `
		resource "ciphertrust_scheduler" "cloudhsm_rotation_job" {
		  end_date = "2050-03-07T14:24:00Z"
		  cckm_key_rotation_params = {
			cloud_name = "aws"
		  }
		  name       = "%s"
		  operation  = "cckm_key_rotation"
		  run_at     = "0 9 * * sat"
		  run_on     = "any"
		  start_date = "2025-03-07T14:24:00Z"
		}`
	enableRotationConfigStr := fmt.Sprintf(enableRotationConfig, enableRotationName)
	enableRotationConfigStr = applyCDSPAAS(enableRotationConfigStr)

	createKeyConfig := `
		resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_min_params" {
			custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_cloudhsm_keystore.id
		}
		resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_max_params" {
			aws_param = {
				alias       = [local.alias, "%s", "%s"]
				description = "create description"
				tags = {
					TagKey1 = "TagValue1"
				}
			}
			custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_cloudhsm_keystore.id
			enable_key = %t
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.cloudhsm_rotation_job.id
				key_source    = "local"
			}
			key_policy = {
				policy_template = ciphertrust_aws_policy_template.cloudhsm_template.id
			}
		}`
	aliasList := []string{
		awsKeyNamePrefix + uuid.New().String(),
		awsKeyNamePrefix + uuid.New().String(),
	}
	createKeyConfigStr := fmt.Sprintf(createKeyConfig, aliasList[0], aliasList[1], false)
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr + policyTemplateConfigStr + enableRotationConfigStr + createKeyConfigStr

	modifyPlanKeyConfig := `
		resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_min_params" {
			custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_cloudhsm_keystore.id
		}
		resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_max_params" {
			aws_param = {
				alias       = [local.alias, "%s", "%s"]
				description = "create description"
				tags = {
					TagKey1 = "TagValue1"
				}
			}
			custom_key_store_id = "tf-fake-keystore-id"
			enable_key = false
			key_policy = {
				policy_template = ciphertrust_aws_policy_template.cloudhsm_template.id
			}
		}`
	modifyPlanConfigStr := awsConnectionResource + createKeyStoreConfigStr + policyTemplateConfigStr + enableRotationConfigStr +
		fmt.Sprintf(modifyPlanKeyConfig, aliasList[0], aliasList[1])

	updateKeyConfig := `
		resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_min_params" {
			aws_param = {
				alias       = [local.alias]
				description = "update description"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_cloudhsm_keystore.id
			enable_key = false
			key_policy = {
				policy = ciphertrust_aws_policy_template.cloudhsm_template.policy
			}
		}
		resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_max_params" {
			aws_param = {
				alias       = [local.alias]
				description = "update description"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
			custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_cloudhsm_keystore.id
			enable_key = %t
			key_policy = {
				policy = ciphertrust_aws_policy_template.cloudhsm_template.policy
			}
		}`
	updateKeyConfigStr := fmt.Sprintf(updateKeyConfig, true)
	updateConfigStr := awsConnectionResource + createKeyStoreConfigStr + policyTemplateConfigStr + enableRotationConfigStr + updateKeyConfigStr

	keyResourceMaxParams := "ciphertrust_aws_cloudhsm_key.cloudhsm_key_max_params"
	keyResourceMinParams := "ciphertrust_aws_cloudhsm_key.cloudhsm_key_min_params"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					// blocked, enable_key, key_state: for unlinked keys these are stored from plan but not
					// applied to AWS - block/enable ops are gated on linked_state == true.
					resource.TestCheckResourceAttr(keyResourceMaxParams, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.%", "4"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.auto_rotate_key_source", "local"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_on_auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_for_all_accounts_on_auto_rotate", "false"),
					resource.TestCheckResourceAttrPair(keyResourceMaxParams, "labels.job_config_id", "ciphertrust_scheduler.cloudhsm_rotation_job", "id"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.alias.#", "3"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.tags.TagKey1", "TagValue1"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.alias.#", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.description", ""),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.tags.%", "0"),
				),
			},
			{
				ResourceName:            keyResourceMaxParams,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsCloudHSMKey,
			},
			{
				ResourceName:            keyResourceMinParams,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsCloudHSMKey,
			},
			{
				Config: updateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResourceMaxParams, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.description", "update description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.tags.TagKey2", "TagValue2"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.description", "update description"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.tags.TagKey2", "TagValue2"),
				),
			},
			{
				// Verify state is stable immediately after the update (no phantom diffs).
				RefreshState: true,
			},
			{
				ResourceName:            keyResourceMaxParams,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsCloudHSMKey,
			},
			{
				ResourceName:            keyResourceMinParams,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsCloudHSMKey,
			},
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResourceMaxParams, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.%", "4"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.auto_rotate_key_source", "local"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_on_auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_for_all_accounts_on_auto_rotate", "false"),
					resource.TestCheckResourceAttrPair(keyResourceMaxParams, "labels.job_config_id", "ciphertrust_scheduler.cloudhsm_rotation_job", "id"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.alias.#", "3"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.tags.%", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.tags.TagKey1", "TagValue1"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.alias.#", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.description", ""),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.tags.%", "0"),
				),
			},
			{
				// Verify ModifyPlan fires an error when custom_key_store_id is changed.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
		},
	})
}
