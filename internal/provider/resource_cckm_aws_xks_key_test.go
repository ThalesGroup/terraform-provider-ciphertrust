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
// in TestCckmAWSXksSUnlinkedKey - extra entries are harmless when the attributes already match.
var importStateVerifyIgnoreAwsXksKey = []string{
	// aws_param.alias: not applied to AWS for unlinked keys, so not returned by GET.
	"aws_param.alias",
	// aws_param.description: Read() preserves prior state value for unlinked keys; no prior state after import.
	"aws_param.description",
	// aws_param.tags: not applied/returned for unlinked keys (AWS-side operation).
	"aws_param.tags",
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
}

// TestCckmAWSXksUnlinkedKey valid create and update of an unlinked key and an invalid update
func TestCckmAWSXksUnlinkedKey(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	createKeyStoreConfig := `
		resource "ciphertrust_cm_key" "cm_healthcheck_key" {
			name         = "%s"
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
		}
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms_id  = ciphertrust_aws_kms.kms.id
			linked_state = false
			local_hosted_params = {
				health_check_key_id = ciphertrust_cm_key.cm_healthcheck_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param = {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}`

	healthCheckKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CIPHERTRUST_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, healthCheckKeyName, keyStoreName, proxyURIEndpoint)

	xksKeyConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = "%s"
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
			unexportable = true
			undeletable  = true
			remove_from_state_on_destroy = true
		}
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_min_params" {
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				linked  = false
				blocked = %t
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_max_params" {
			aws_param = {
				alias       = [local.alias]
				description = "create description"
			}
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				blocked = %t
				linked  = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
			schedule_for_deletion_days = %d
			enable_key = %t
		}`

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	createXksKeyConfigStr := fmt.Sprintf(xksKeyConfig, cmKeyName, false, true, 8, true)
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr + createXksKeyConfigStr

	updateXksKeyConfigStr := fmt.Sprintf(xksKeyConfig, cmKeyName, true, false, 9, true)
	validUpdateConfigStr := awsConnectionResource + createKeyStoreConfigStr + updateXksKeyConfigStr

	// Unable to disable a key not in a linked state
	invalidUpdateXksKeyConfigStr := fmt.Sprintf(xksKeyConfig, cmKeyName, true, false, 9, false)
	invalidUpdateConfigStr := awsConnectionResource + createKeyStoreConfigStr + invalidUpdateXksKeyConfigStr

	keyResourceMaxParams := "ciphertrust_aws_xks_key.unlinked_cm_source_max_params"
	keyResourceMinParams := "ciphertrust_aws_xks_key.unlinked_cm_source_min_params"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResourceMaxParams, "blocked", "true"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "schedule_for_deletion_days", "8"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "blocked", "false"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.alias.#", "0"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.description", ""),
					resource.TestCheckResourceAttr(keyResourceMinParams, "schedule_for_deletion_days", "7"),
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
				Config: validUpdateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResourceMaxParams, "blocked", "false"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.alias.#", "1"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.description", "create description"),
					resource.TestCheckResourceAttr(keyResourceMaxParams, "schedule_for_deletion_days", "9"),

					resource.TestCheckResourceAttr(keyResourceMinParams, "blocked", "true"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResourceMinParams, "aws_param.description", ""),
					resource.TestCheckResourceAttr(keyResourceMinParams, "schedule_for_deletion_days", "7"),
				),
			},
			{
				Config:      invalidUpdateConfigStr,
				ExpectError: regexp.MustCompile(`unlinked key`),
			},
		},
	})
}

// TestCckmAWSXksUnlinkedKeyCreateModifyPlan verifies that ModifyPlan rejects invalid attributes
// when creating an unlinked XKS key. Two errors are expected:
//
//  1. "Invalid attribute at creation time" - covers attributes that cannot be set at creation
//     for any XKS key: more than one alias, enable_rotation, enable_key = false.
//
//  2. "Invalid configuration for an unlinked key" - covers attributes that require
//     local_hosted_params.linked = true: aws_param.tags, key_policy.
func TestCckmAWSXksUnlinkedKeyCreateModifyPlan(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
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
			kms_id  = ciphertrust_aws_kms.kms.id
			linked_state = false
			local_hosted_params = {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param = {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}`
	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CIPHERTRUST_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, proxyURIEndpoint)

	enableRotationName := "tf-rotation-" + uuid.New().String()[:8]
	enableRotationConfig := `
		resource "ciphertrust_scheduler" "scheduled_rotation_job" {
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

	// This key config includes:
	// - more than one alias, enable_rotation, enable_key=false (invalid at creation for any key)
	// - aws_param.tags, key_policy (invalid for unlinked keys)
	createXksKeyConfig := `
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_invalid_params" {
			aws_param = {
				alias       = [local.alias, "testing123"]
				description = "create description"
				tags = {
					TagKey1 = "TagValue1"
				}
			}
			enable_key = false
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
				key_source    = "local"
			}
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				blocked = true
				linked  = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
			key_policy = {
				policy = <<-EOT
					%s
				EOT
			}
		}`

	createXksKeyConfigStr := fmt.Sprintf(createXksKeyConfig, awsKeyPolicy)
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr +
		enableRotationConfigStr + createXksKeyConfigStr

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				// Both error groups are expected. Group 1 ("Invalid attribute at creation time")
				// appears first and contains alias, enable_rotation, enable_key=false.
				// Group 2 ("Invalid configuration for an unlinked key") appears second
				// and contains aws_param.tags and key_policy.
				ExpectError: regexp.MustCompile(
					`(?s)Invalid attribute at creation time` +
						`.*aws_param\.alias` +
						`.*enable_rotation` +
						`.*enable_key` +
						`.*Invalid configuration for an unlinked key` +
						`.*aws_param\.tags` +
						`.*key_policy`,
				),
			},
		},
	})
}

// TestCckmAWSXksLinkedKeyCreateModifyPlan verifies that ModifyPlan rejects attributes that
// cannot be set at creation time for any XKS key (linked or unlinked):
// more than one alias, enable_rotation, and enable_key = false.
// Note: aws_param.tags and key_policy are valid at creation when linked = true.
func TestCckmAWSXksLinkedKeyCreateModifyPlan(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
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
		resource "ciphertrust_aws_custom_keystore" "linked_xks_custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms_id  = ciphertrust_aws_kms.kms.id
			linked_state = false
			local_hosted_params = {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param = {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}`
	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CIPHERTRUST_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, proxyURIEndpoint)

	enableRotationName := "tf-rotation-" + uuid.New().String()[:8]
	enableRotationConfig := `
		resource "ciphertrust_scheduler" "scheduled_rotation_job" {
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

	// This key config is linked = true but still sets attributes that are always invalid at creation:
	// more than one alias, enable_rotation, and enable_key = false.
	createXksKeyConfig := `
		resource "ciphertrust_aws_xks_key" "linked_cm_source_invalid_create_params" {
			aws_param = {
				alias       = [local.alias, "testing123"]
				description = "create description"
			}
			enable_key = false
			enable_rotation = {
				job_config_id = ciphertrust_scheduler.scheduled_rotation_job.id
				key_source    = "local"
			}
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.linked_xks_custom_keystore.id
				blocked = false
				linked  = true
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}`

	createConfigStr := awsConnectionResource + createKeyStoreConfigStr +
		enableRotationConfigStr + createXksKeyConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				ExpectError: regexp.MustCompile(
					`(?s)Invalid attribute at creation time` +
						`.*aws_param\.alias` +
						`.*enable_rotation` +
						`.*enable_key`,
				),
			},
		},
	})
}
