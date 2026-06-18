package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// importStateVerifyIgnoreAwsXksKey lists the attributes that cannot round-trip through
// terraform import for unlinked XKS keys. It is the superset of all four import steps
// in TestCckmAWSXKSUnlinkedKey - extra entries are harmless when the attributes already match.
var importStateVerifyIgnoreAwsXksKey = []string{
	// alias: not applied to AWS for unlinked keys, so not returned by GET.
	"alias",
	// description: Read() preserves prior state value for unlinked keys; no prior state after import.
	"description",
	// enable_key: not applied for unlinked keys (block/enable ops require linked_state = true).
	"enable_key",
	// enable_rotation: not surfaced in GET response; cannot round-trip.
	"enable_rotation",
	// key_policy: not surfaced in GET response; cannot round-trip.
	"key_policy",
	// local_hosted_params: write-only input block; top-level blocked/linked computed attributes
	// reflect the actual key state instead.
	"local_hosted_params",
	// schedule_for_deletion_days: null for active keys; does not round-trip cleanly after import.
	"schedule_for_deletion_days",
	// tags: not applied/returned for unlinked keys (AWS-side operation).
	"tags",
}

func TestCckmAWSXKSUnlinkedKey(t *testing.T) {
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
	createKeyStoreConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = "%s"
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
			unexportable = true
			undeletable  = true
			remove_from_state_on_destroy = true
		}
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms     = ciphertrust_aws_kms.kms.name
			linked_state = false
			local_hosted_params {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}`
	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CM_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, proxyURIEndpoint)

	createPolicyTemplateConfig := `
		resource "ciphertrust_aws_policy_template" "template_with_users_and_roles" {
			name        = "%s"
			kms         = ciphertrust_aws_kms.kms.id
			key_admins  = ["%s"]
			key_users   = ["%s"]
			key_admins_roles  = ["%s"]
			key_users_roles   = ["%s"]
		}`
	policyTemplateConfigStr := fmt.Sprintf(createPolicyTemplateConfig,
		"tf-"+uuid.New().String()[:8],
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1])

	enableRotationName := "tf-rotation-" + uuid.New().String()[:8]
	enableRotationConfig := `
		resource "ciphertrust_scheduler" "scheduled_rotation_job" {
		  end_date = "2050-03-07T14:24:00Z"
		  cckm_key_rotation_params {
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

	createXKSKeyConfig := `
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_min_params" {
			local_hosted_params {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				blocked = false
				linked  = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_max_params" {
			alias        = [local.alias, "%s", "%s"]
			description = "create description"
			enable_key = %t
			enable_rotation {
				job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
				key_source    = "local"
			}
			key_policy {
				policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
			}
			local_hosted_params {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				blocked = true
				linked  = false
				source_key_id   = %s
				source_key_tier = "local"
			}
			tags = {
				TagKey1 = "TagValue1"
			}
		}`
	aliasList := []string{
		awsKeyNamePrefix + uuid.New().String(),
		awsKeyNamePrefix + uuid.New().String(),
	}
	createXKSKeyConfigStr := fmt.Sprintf(createXKSKeyConfig, aliasList[0], aliasList[1], false, "ciphertrust_cm_key.cm_aes_key.id")
	modifyPlanConfigStr := awsConnectionResource + createKeyStoreConfigStr + policyTemplateConfigStr + enableRotationConfigStr +
		fmt.Sprintf(createXKSKeyConfig, aliasList[0], aliasList[1], false, `"tf-fake-key-id"`)
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr + policyTemplateConfigStr + enableRotationConfigStr + createXKSKeyConfigStr

	updateXKSKeyConfig := `
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_min_params" {
			alias        = [local.alias]
			description = "update description"
			enable_key  = false
			key_policy {
				policy = ciphertrust_aws_policy_template.template_with_users_and_roles.policy
			}
			local_hosted_params {
				blocked = true
				linked  = false
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				source_key_id = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
			tags = {
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}
		}
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_max_params" {
			alias        = [local.alias]
			description = "update description"
			enable_key  = %t
			key_policy {
				policy = ciphertrust_aws_policy_template.template_with_users_and_roles.policy
			}
			local_hosted_params {
				blocked = false
				linked  = false
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				source_key_id = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
			tags = {
				TagKey1 = "TagValue1"
				TagKey2 = "TagValue2"
			}
		}`
	updateXKSKeyConfigStr := fmt.Sprintf(updateXKSKeyConfig, true)
	updateConfigStr := awsConnectionResource + createKeyStoreConfigStr + policyTemplateConfigStr + enableRotationConfigStr + updateXKSKeyConfigStr

	keyResourceMaxParams := "ciphertrust_aws_xks_key.unlinked_cm_source_max_params"
	keyResourceMinParams := "ciphertrust_aws_xks_key.unlinked_cm_source_min_params"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResourceMaxParams, "alias.#", "3"),
					// blocked, enable_key, key_state: for unlinked keys these are stored from plan but not
					// applied to AWS - block/enable ops are gated on linked_state == true.
					resource.TestCheckResourceAttr(keyResourceMaxParams, "blocked", "true"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.%", "4"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.auto_rotate_key_source", "local"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_on_auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_for_all_accounts_on_auto_rotate", "false"),
					resource.TestCheckResourceAttrPair(keyResourceMaxParams, "labels.job_config_id", "ciphertrust_scheduler.scheduled_rotation_job", "id"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "description", "create description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "tags.%", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "tags.TagKey1", "TagValue1"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "alias.#", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "blocked", "false"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "description", ""),
					resource.TestCheckResourceAttr(keyResourceMinParams, "tags.%", "0"),
				),
			},
			{
				ResourceName:            keyResourceMaxParams,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsXksKey,
			},
			{
				ResourceName:            keyResourceMinParams,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsXksKey,
			},
			{
				Config: updateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResourceMaxParams, "alias.#", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "blocked", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "description", "update description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "tags.%", "2"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "tags.TagKey2", "TagValue2"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "alias.#", "1"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "blocked", "true"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "description", "update description"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "tags.%", "2"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "tags.TagKey2", "TagValue2"),
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
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsXksKey,
			},
			{
				ResourceName:            keyResourceMinParams,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsXksKey,
			},
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResourceMaxParams, "alias.#", "3"),
					// blocked, enable_key, key_state: for unlinked keys these are stored from plan but not
					// applied to AWS - block/enable ops are gated on linked_state == true.
					resource.TestCheckResourceAttr(keyResourceMaxParams, "blocked", "true"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.%", "4"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.auto_rotate_key_source", "local"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_on_auto_rotate", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "labels.disable_encrypt_for_all_accounts_on_auto_rotate", "false"),
					resource.TestCheckResourceAttrPair(keyResourceMaxParams, "labels.job_config_id", "ciphertrust_scheduler.scheduled_rotation_job", "id"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "description", "create description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "tags.%", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "tags.TagKey1", "TagValue1"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "alias.#", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "blocked", "false"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "description", ""),
					resource.TestCheckResourceAttr(keyResourceMinParams, "tags.%", "0"),
				),
			},
			{
				// Verify ModifyPlan fires an error when local_hosted_params.source_key_id is changed.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
		},
	})
}
