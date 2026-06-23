package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// importStateVerifyIgnoreAwsByokKey lists attributes that cannot round-trip through
// terraform import for AWS BYOK (EXTERNAL) keys. Write-only input fields and
// computed fields that may drift between consecutive Read calls are excluded.
var importStateVerifyIgnoreAwsByokKey = []string{
	"aws_param.tags",
	"aws_param.valid_to",
	"enable_key",
	"enable_rotation",
	"key_expiration",
	"key_policy",
	"kms_id",
	"labels",
	"multi_region_configuration.multi_region_key_type",
	"multi_region_configuration.primary_key.arn",
	"multi_region_configuration.primary_key.region",
	"multi_region_configuration.replica_keys.#",
	"primary_region",
	"replicate_key",
	"schedule_for_deletion_days",
	"updated_at",
}

// cmRsaKeyConfig is the shared CipherTrust Manager RSA 2048 source key config used by RSA BYOK tests.
// RSA BYOK keys use customer_master_key_spec = "RSA_2048" and only support a single key material import.
const cmRsaKeyConfig = `
	resource "ciphertrust_cm_key" "cm_rsa_key" {
		name                         = local.cmKeyName
		algorithm                    = "RSA"
		key_size                     = 2048
		unexportable                 = false
		undeletable                  = true
		remove_from_state_on_destroy = true
	}`

// cmAesKeyConfig is the shared CipherTrust Manager AES source key config used by BYOK tests.
// It references the cmKeyName and cm_key_usage_mask locals supplied by initCckmAwsTest.
const cmAesKeyConfig = `
	resource "ciphertrust_cm_key" "cm_aes_key" {
		name                         = local.cmKeyName
		algorithm                    = "AES"
	}`

// awsKeyValidTo returns a UTC RFC3339 timestamp daysFromNow days in the future,
// truncated to midnight. AWS requires ValidTo to be less than 365 days in the future;
// use values well below that limit to avoid a ValidationException.
func awsKeyValidTo(daysFromNow int) string {
	return time.Now().UTC().AddDate(0, 0, daysFromNow).Truncate(24 * time.Hour).Format(time.RFC3339)
}

// TestCckmAWSByokKeyAESCreateWithSourceKey tests creating an AWS EXTERNAL (BYOK) AES key with
// all source key parameters (source_key_identifier, source_key_tier, aws_param.valid_to,
// aws_param.description), updating all updatable attributes, and verifying that immutable
// attributes cannot be changed after creation. The default customer_master_key_spec is
// SYMMETRIC_DEFAULT (AES-256), which is set implicitly when no spec is provided.
func TestCckmAWSByokKeyAESCreateWithSourceKey(t *testing.T) {
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

	validTo := awsKeyValidTo(180) // ~6 months out - within AWS 365-day limit

	// Step 1: create with source_key_identifier, source_key_tier, valid_to, description,
	// and a structured key policy with admins + users.
	createKeyConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_byok_key" "byok_key" {
			enable_key            = true
			key_policy = {
				key_admins       = ["%s"]
				key_users        = ["%s"]
				key_admins_roles = ["%s"]
				key_users_roles  = ["%s"]
			}
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias       = [local.alias, "%s"]
				description = "create description"
				valid_to    = "%s"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
		}`,
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1],
		awsKeyNamePrefix+uuid.New().String(), validTo,
	)

	// Step 3: update - change enable_key, policy (raw JSON), aliases, description, tags.
	updateKeyConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_byok_key" "byok_key" {
			enable_key            = false
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias       = [local.alias]
				description = "update description"
				tags = {
					TagKey1 = "TagValue1"
					TagKey3 = "TagValue3"
				}
			}
		}`, awsKeyPolicy)

	// ModifyPlan step: verify that changing customer_master_key_spec is rejected.
	modifyPlanKeySpecConfig := `
		resource "ciphertrust_aws_byok_key" "byok_key" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias                    = [local.alias]
				customer_master_key_spec = "RSA_2048"
			}
		}`

	keyResource := "ciphertrust_aws_byok_key.byok_key"
	base := awsConnectionResource + cmAesKeyConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with all source key params including valid_to + description.
				Config: base + createKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttr(keyResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					// valid_to was supplied as input in aws_param; verify it is returned by the API.
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.valid_to"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
				),
			},
			{
				// Step 2: import state round-trip.
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsByokKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			{
				// Step 3: update - disable key, switch to raw JSON policy, change aliases/tags/description.
				Config: base + updateKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "update description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Disabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey3", "TagValue3"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				// Step 4: verify ModifyPlan rejects a customer_master_key_spec change.
				Config:      base + modifyPlanKeySpecConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
		},
	})
}

// TestCckmAWSByokKeyUpdates verifies that all updatable attributes of a BYOK key can be
// changed in a single apply, and that a re-apply of the original config restores all values.
// The test also verifies that a key rotation scheduler can be attached on create, detached
// on update, and re-attached on a subsequent re-apply.
func TestCckmAWSByokKeyUpdates(t *testing.T) {
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

	schedulerName := "tf-byok-" + uuid.New().String()[:8]
	extraAlias := "tf-" + uuid.New().String()

	// createParamsConfig specifies all possible non-MR parameters for a BYOK key,
	// including a ciphertrust_scheduler linked via enable_rotation.
	createParamsConfig := fmt.Sprintf(`
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
		resource "ciphertrust_aws_byok_key" "byok_key" {
			enable_key = true
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
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			schedule_for_deletion_days = 7
			aws_param = {
				alias       = [local.alias, "%s"]
				description = "create description"
				tags = {
					TagKey1 = "TagValue1"
					TagKey2 = "TagValue2"
				}
			}
		}`,
		schedulerName,
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1],
		extraAlias,
	)
	createParamsConfig = applyCDSPAAS(createParamsConfig)

	// updateParamsConfig updates every updatable attribute and removes enable_rotation.
	updateParamsConfig := fmt.Sprintf(`
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
		resource "ciphertrust_aws_byok_key" "byok_key" {
			enable_key            = false
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			schedule_for_deletion_days = 7
			aws_param = {
				alias       = [local.alias]
				description = "update description"
				tags = {
					TagKey1 = "TagValue1"
					TagKey3 = "TagValue3"
				}
			}
		}`,
		schedulerName, awsKeyPolicy,
	)
	updateParamsConfig = applyCDSPAAS(updateParamsConfig)

	keyResource := "ciphertrust_aws_byok_key.byok_key"
	schedulerResource := "ciphertrust_scheduler.scheduler"
	base := awsConnectionResource + cmAesKeyConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with all possible non-MR parameters.
				Config: base + createParamsConfig,
				Check: resource.ComposeTestCheckFunc(
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
					resource.TestCheckResourceAttrPair(keyResource, "labels.job_config_id", schedulerResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
				),
			},
			{
				// Step 2: import state round-trip.
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsByokKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			{
				// Step 3: update all updatable attributes; remove enable_rotation.
				Config: base + updateParamsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "7"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "update description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Disabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey3", "TagValue3"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				// Step 4: re-apply createParamsConfig to verify all values are safely restored.
				Config: base + createParamsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(keyResource, "labels.auto_rotate_key_source", "ciphertrust"),
					resource.TestCheckResourceAttrPair(keyResource, "labels.job_config_id", schedulerResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.alias.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey1", "TagValue1"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.TagKey2", "TagValue2"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), true),
				),
			},
		},
	})
}

// TestCckmAWSByokKeyPolicyUpdates exercises all key_policy update transitions for a BYOK key:
// key_admins/key_users -> raw policy JSON -> key_admins/key_users restored -> no key_policy block.
// The last step verifies the nil key_policy guard: when key_policy is removed entirely
// the provider must still call POST /policy with an empty payload to reset the key to the
// default AWS root-only policy.
func TestCckmAWSByokKeyPolicyUpdates(t *testing.T) {
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

	// Step 1: create with key_admins + key_users + key_admins_roles + key_users_roles.
	withAdminsConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_byok_key" "byok_policy" {
			key_policy = {
				key_admins       = ["%s"]
				key_users        = ["%s"]
				key_admins_roles = ["%s"]
				key_users_roles  = ["%s"]
			}
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias = [local.alias]
			}
		}`,
		awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1],
	)

	// Step 2: switch to a raw JSON policy (root-only, no admins or users).
	rawPolicyConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_byok_key" "byok_policy" {
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias = [local.alias]
			}
		}`, awsKeyPolicy)

	// Step 4: remove key_policy entirely - provider must call POST /policy with {}
	// to reset the key to the default AWS root-only policy.
	noPolicyConfig := `
		resource "ciphertrust_aws_byok_key" "byok_policy" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias = [local.alias]
			}
		}`

	keyResource := "ciphertrust_aws_byok_key.byok_policy"
	base := awsConnectionResource + cmAesKeyConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with structured key_admins/key_users policy.
				Config: base + withAdminsConfig,
				Check: resource.ComposeTestCheckFunc(
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
				),
			},
			{
				// Step 2: switch to raw JSON policy - admins/users removed from policy.
				Config: base + rawPolicyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
			{
				// Step 3: restore structured key_admins/key_users policy.
				Config: base + withAdminsConfig,
				Check: resource.ComposeTestCheckFunc(
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
				),
			},
			{
				// Step 4: remove key_policy block entirely; provider calls POST /policy with {}
				// which resets the key to the default AWS root-only policy.
				Config: base + noPolicyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "key_admins.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_admins_roles.#", "0"),
					resource.TestCheckResourceAttr(keyResource, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.policy"),
					testCheckAttributeContains(keyResource, "aws_param.policy", append(awsKeyUsers, awsKeyRoles...), false),
				),
			},
		},
	})
}

// TestCckmAWSByokKeyKmsDeleteRecovery verifies provider recovery after a KMS is deleted
// out-of-band for a BYOK key. On refresh the KMS and ACL are dropped from state; the key
// is preserved in state so it can be re-associated when the KMS returns. On re-apply
// Terraform recreates the KMS and ACL; the ACL check in the final step confirms the ACL
// is recreated on the new KMS.
func TestCckmAWSByokKeyKmsDeleteRecovery(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	keyConfig := fmt.Sprintf(`
		resource "ciphertrust_user" "acl_user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.acl_user.id
			actions = ["keycreate"]
		}
		resource "ciphertrust_aws_byok_key" "byok_key" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias = [local.alias]
			}
		}`, "tf-"+uuid.New().String()[:8])

	keyResource := "ciphertrust_aws_byok_key.byok_key"
	aclResource := "ciphertrust_aws_acl.user_acl"
	kmsResource := "ciphertrust_aws_kms.kms"
	base := awsConnectionResource + cmAesKeyConfig
	fullConfig := base + keyConfig

	var capturedKMSID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create KMS + BYOK key + user ACL. Capture the KMS ID for OOB deletion.
				Config: fullConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
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
				// Step 2: delete the KMS out-of-band, then refresh state.
				// Expected: KMS and ACL dropped from state (404); key preserved in state.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"delete-kms-byok-recovery-test",
						common.URL_AWS_KMS+"/"+capturedKMSID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: re-apply to recover.
				// KMS and ACL are recreated; key is re-associated with the new KMS.
				Config: fullConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(kmsResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(aclResource, "id"),
				),
			},
			{
				// Step 4: refresh state so the KMS Read picks up the ACL created after
				// the KMS in Step 3. The acls.# check confirms the ACL is visible on the
				// KMS registration.
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResource, "acls.#", "1"),
				),
			},
		},
	})
}

// TestCckmAWSByokKeyRSACreateWithSourceKey tests creating an AWS EXTERNAL (BYOK) RSA_2048 key
// with a CipherTrust Manager RSA 2048 source key. RSA BYOK keys differ from AES BYOK keys in
// that customer_master_key_spec must be set to "RSA_2048" and key_usage must be set explicitly.
// Unlike AES BYOK keys, RSA BYOK keys do not support rotating key material - only a single
// import of key material is permitted. The test creates the key, verifies it is Enabled, and
// performs a basic update of mutable attributes (description, tags, enable_key).
func TestCckmAWSByokKeyRSACreateWithSourceKey(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// Step 1: create an RSA_2048 BYOK key with source key material from the CM RSA key.
	createKeyConfig := `
		resource "ciphertrust_aws_byok_key" "byok_rsa_key" {
			enable_key            = true
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_rsa_key.id
			source_key_tier       = "local"
			aws_param = {
				alias                    = [local.alias]
				customer_master_key_spec = "RSA_2048"
				key_usage                = "ENCRYPT_DECRYPT"
				description              = "RSA 2048 BYOK key"
				tags = {
					KeyType = "RSA"
					KeySize = "2048"
				}
			}
		}`

	// Step 2: update mutable attributes - disable the key, change description and tags.
	// customer_master_key_spec and key_usage are immutable after creation and must not change.
	updateKeyConfig := `
		resource "ciphertrust_aws_byok_key" "byok_rsa_key" {
			enable_key            = false
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_rsa_key.id
			source_key_tier       = "local"
			aws_param = {
				alias                    = [local.alias]
				customer_master_key_spec = "RSA_2048"
				key_usage                = "ENCRYPT_DECRYPT"
				description              = "RSA 2048 BYOK key - updated"
				tags = {
					KeyType = "RSA"
					KeySize = "2048"
					Updated = "true"
				}
			}
		}`

	keyResource := "ciphertrust_aws_byok_key.byok_rsa_key"
	base := awsConnectionResource + cmRsaKeyConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create RSA_2048 BYOK key with source material from CM RSA key.
				// Verify the key reaches Enabled state with rotation_history.#=1.
				Config: base + createKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "RSA 2048 BYOK key"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "2"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.KeyType", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.KeySize", "2048"),
				),
			},
			{
				// Step 2: import state round-trip.
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsByokKey,
				ImportStateIdFunc:       getResourceAttr(keyResource, "id"),
			},
			{
				// Step 3: update mutable attributes - disable key, change description and tags.
				Config: base + updateKeyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "RSA_2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "RSA 2048 BYOK key - updated"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.enabled", "false"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Disabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "3"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.KeyType", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.KeySize", "2048"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.Updated", "true"),
				),
			},
		},
	})
}

// TestCckmAWSByokKeyMultiRegionAndMakePrimary tests creating an AWS EXTERNAL multi-region BYOK primary key,
// replicating it to a second region and promoting the replica to primary via make_primary=true.
func TestCckmAWSByokKeyMultiRegionAndMakePrimary(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	replicaAlias := "tf-" + uuid.New().String()[8:]

	// primaryConfig creates the primary EXTERNAL multi-region key.
	primaryConfig := `
		resource "ciphertrust_aws_byok_key" "mr_primary" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
		}`

	// replicaConfig adds a replica pointing at the primary. Material is inherited automatically.
	replicaConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_byok_key" "mr_replica" {
			region     = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id       = ciphertrust_aws_byok_key.mr_primary.id
				make_primary = true
			}
			aws_param = {
				alias = ["%s"]
			}
		}`, replicaAlias)

	primaryResource := "ciphertrust_aws_byok_key.mr_primary"
	replicaResource := "ciphertrust_aws_byok_key.mr_replica"
	base := awsConnectionResource + cmAesKeyConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create primary EXTERNAL multi-region key with source material.
				// Verify key is Enabled, multi_region=true, and multi_region_configuration
				// identifies this key as PRIMARY with no replicas yet.
				Config: base + primaryConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(primaryResource, "id"),
					resource.TestCheckResourceAttrSet(primaryResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.replica_keys.#", "0"),
				),
			},
			{
				// Step 2: replicate the primary to a second region.
				// The replica inherits key material from the primary automatically.
				// The replica is made the primary key after replication
				// Verify the replica is now the PRIMARY
				Config: base + primaryConfig + replicaConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(replicaResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttrSet(replicaResource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "1"),
				),
			},
			{
				RefreshState: true,
			},
			{
				// Step 3: Verify the original primary key is now a replica
				Config: base + primaryConfig + replicaConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
				),
			},
		},
	})
}

// TestCckmAWSByokKeyMultiRegionAndPrimaryRegion tests creating an AWS EXTERNAL multi-region BYOK primary key,
// replicating it to a second region, verifying multi_region_configuration on both keys, and
// then promoting the replica to primary via pimary_region=true.
func TestCckmAWSByokKeyMultiRegionAndPrimaryRegion(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	replicaAlias := "tf-" + uuid.New().String()[8:]

	// primaryConfig creates the primary EXTERNAL multi-region key.
	primaryConfig := `
		resource "ciphertrust_aws_byok_key" "mr_primary" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
		}`

	// replicaConfig adds a replica pointing at the primary. Material is inherited automatically.
	replicaConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_byok_key" "mr_replica" {
			region     = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.mr_primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}`, replicaAlias)

	// makeReplicaPrimaryConfig promotes the replica to primary.
	makeReplicaPrimaryConfig := `
		resource "ciphertrust_aws_byok_key" "mr_primary" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
			primary_region = ciphertrust_aws_kms.kms.regions[1]
		}`

	primaryResource := "ciphertrust_aws_byok_key.mr_primary"
	replicaResource := "ciphertrust_aws_byok_key.mr_replica"
	base := awsConnectionResource + cmAesKeyConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create primary EXTERNAL multi-region key with source material.
				// Verify key is Enabled, multi_region=true, and multi_region_configuration
				// identifies this key as PRIMARY with no replicas yet.
				Config: base + primaryConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(primaryResource, "id"),
					resource.TestCheckResourceAttrSet(primaryResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.replica_keys.#", "0"),
				),
			},
			{
				// Step 2: replicate the primary to a second region.
				// The replica inherits key material from the primary automatically.
				// Verify the replica is REPLICA and the primary now shows 1 replica.
				Config: base + primaryConfig + replicaConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(replicaResource, "id"),
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					resource.TestCheckResourceAttrSet(replicaResource, "multi_region_configuration.primary_key.arn"),
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.replica_keys.#", "1"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttrSet(replicaResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.origin", "EXTERNAL"),
				),
			},
			{
				// Step 3: promote the replica to primary via primary_region
				// The replica's multi_region_configuration.multi_region_key_type becomes PRIMARY.
				// The old primary becomes REPLICA. Both keys remain Enabled.
				Config: base + makeReplicaPrimaryConfig + replicaConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "multi_region_configuration.multi_region_key_type", "REPLICA"),
					// At this point the replicaResource will still show REPLICA - a refresh is required
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replicaResource, "aws_param.key_state", "Enabled"),
				),
			},
			{
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(replicaResource, "multi_region_configuration.multi_region_key_type", "PRIMARY"),
				),
			},
			{
				// Step 4 import state round-trip for the primary.
				ResourceName:            primaryResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsByokKey,
				ImportStateIdFunc:       getResourceAttr(primaryResource, "id"),
			},
			{
				// Step 5: import state round-trip for the replica.
				ResourceName:            replicaResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAwsByokKey,
				ImportStateIdFunc:       getResourceAttr(replicaResource, "id"),
			},
		},
	})
}
