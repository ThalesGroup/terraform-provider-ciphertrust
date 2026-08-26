package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// xksUnlinkedCreateInvalidRegexPre223 is the ExpectError regex for TestCckmAWSXksUnlinkedKeyCreateModifyPlan
// when the connected CM is older than 2.23. The alias attribute is omitted from the config on pre-2.23
// because a single alias on an unlinked key is accepted (there is no >1 alias error to trigger),
// so aws_param.alias does not appear in the error listing.
const xksUnlinkedCreateInvalidRegexPre223 = `(?s)Invalid configuration for a new XKS key` +
	`.*enable_rotation` +
	`.*enable_key` +
	`.*aws_param\.tags` +
	`.*key_policy` +
	`.*bypass_policy_lockout_safety_check`

// xksUnlinkedCreateInvalidRegex223Plus is the ExpectError regex for TestCckmAWSXksUnlinkedKeyCreateModifyPlan
// when the connected CM is 2.23 or later. The config includes two aliases so the >1 alias check fires
// and aws_param.alias appears first in the error listing.
const xksUnlinkedCreateInvalidRegex223Plus = `(?s)Invalid configuration for a new XKS key` +
	`.*aws_param\.alias` +
	`.*enable_rotation` +
	`.*enable_key` +
	`.*aws_param\.tags` +
	`.*key_policy` +
	`.*bypass_policy_lockout_safety_check`

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

// TestCckmAWSXksUnlinkedKey valid create and update of an unlinked key and an invalid update.
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
				# Place holder for alias < invalid in CM < 2.23
				%s
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

	// alias on an unlinked key is only stored and returned by CM 2.23 and later.
	// On older CM the API omits aws_param.Alias from the GET response for unlinked keys.
	keyAlias := `alias       = [local.alias]`
	numExpectedAliases := "1"
	if getCipherTrustVersion() < 223 {
		keyAlias = ""
		numExpectedAliases = "0"
	}

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	createXksKeyConfigStr := fmt.Sprintf(xksKeyConfig, cmKeyName, false, keyAlias, true, 8, true)
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr + createXksKeyConfigStr

	updateXksKeyConfigStr := fmt.Sprintf(xksKeyConfig, cmKeyName, true, keyAlias, false, 9, true)
	validUpdateConfigStr := awsConnectionResource + createKeyStoreConfigStr + updateXksKeyConfigStr

	// Unable to disable a key not in a linked state
	invalidUpdateXksKeyConfigStr := fmt.Sprintf(xksKeyConfig, cmKeyName, true, keyAlias, false, 9, false)
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
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.alias.#", numExpectedAliases),
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
					resource.TestCheckResourceAttr(keyResourceMaxParams, "aws_param.alias.#", numExpectedAliases),
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
// when creating an unlinked XKS key. A single "Invalid configuration for a new XKS key" error
// is expected listing all invalid attributes:
//   - aws_param.alias (more than one alias)
//   - enable_rotation, enable_key = false (cannot be set at creation)
//   - aws_param.tags, key_policy, bypass_policy_lockout_safety_check (require linked = true)
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

	// On CM 2.23+: include two aliases so the >1 alias check fires and aws_param.alias appears in the
	// error. On CM < 2.23: omit alias entirely - a single alias would fire the version gate instead,
	// and two aliases would produce two separate alias errors rather than one clean listing.
	aliasLine := `alias = [local.alias, "alias/testing123"]`
	expectErrorRegex := xksUnlinkedCreateInvalidRegex223Plus
	if getCipherTrustVersion() < 223 {
		aliasLine = ""
		expectErrorRegex = xksUnlinkedCreateInvalidRegexPre223
	}

	// This key config includes:
	// - more than one alias (CM 2.23+), enable_rotation, enable_key=false (invalid at creation for any key)
	// - aws_param.tags, key_policy, bypass_policy_lockout_safety_check (invalid for unlinked keys;
	//   rejected regardless of whether it is true or false)
	createXksKeyConfig := `
		resource "ciphertrust_aws_xks_key" "unlinked_cm_source_invalid_params" {
			aws_param = {
				%s
				description = "create description"
				tags = {
					TagKey1 = "TagValue1"
				}
			}
			bypass_policy_lockout_safety_check = false
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

	createXksKeyConfigStr := fmt.Sprintf(createXksKeyConfig, aliasLine, awsKeyPolicy)
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr +
		enableRotationConfigStr + createXksKeyConfigStr

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				// A single error "Invalid configuration for a new XKS key" lists all
				// invalid attributes. The exact set depends on the CM version (see
				// xksUnlinkedCreateInvalidRegex223Plus / xksUnlinkedCreateInvalidRegexPre223).
				ExpectError: regexp.MustCompile(expectErrorRegex),
			},
		},
	})
}

// TestCckmAWSXksUnlinkedKeyAliasVersionGate verifies that ModifyPlan rejects setting an alias on an
// unlinked XKS key when the connected CipherTrust Manager is older than 2.23.
// This test is skipped on CM 2.23+ and on CDSPaaS (where the feature is always supported).
func TestCckmAWSXksUnlinkedKeyAliasVersionGate(t *testing.T) {
	if getCipherTrustVersion() >= 223 || os.Getenv("CDSPAAS") == "true" {
		t.Skip("TestCckmAWSXksUnlinkedKeyAliasVersionGate only applies to CM < 2.23")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CIPHERTRUST_ADDRESS")

	createConfig := fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = %q
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
			unexportable = true
			undeletable  = true
			remove_from_state_on_destroy = true
		}
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_ks" {
			name    = %q
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms_id  = ciphertrust_aws_kms.kms.id
			linked_state = false
			local_hosted_params = {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param = {
				xks_proxy_uri_endpoint = %q
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}
		resource "ciphertrust_aws_xks_key" "alias_version_gate" {
			aws_param = {
				alias = [local.alias]
			}
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_ks.id
				linked          = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}`, cmKeyName, keyStoreName, proxyURIEndpoint)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createConfig,
				ExpectError: regexp.MustCompile(
					`(?s)Invalid configuration for a new XKS key` +
						`.*aws_param\.alias.*CipherTrust\s+Manager\s+2\.23`,
				),
			},
		},
	})
}

// TestCckmAWSXksUnlinkedKeyUpdateModifyPlan verifies that ModifyPlan rejects update-time changes
// that are only valid for linked XKS keys. The test creates a valid unlinked key, then
// attempts an update that changes aws_param.description, aws_param.alias (on CM 2.23+),
// and sets aws_param.tags - all of which require local_hosted_params.linked = true.
func TestCckmAWSXksUnlinkedKeyUpdateModifyPlan(t *testing.T) {
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

	// alias is only stored/returned by CM 2.23+; on older CM the field is omitted from GET.
	createAlias := ""
	updateAlias := ""
	if getCipherTrustVersion() >= 223 {
		createAlias = `alias = [local.alias]`
		updateAlias = `alias = ["alias/changed-alias"]`
	}

	createXksKeyConfig := `
		resource "ciphertrust_aws_xks_key" "unlinked_update_invalid" {
			aws_param = {
				# Placeholder for alias < invalid for CM < 2.23
				%s
				description = "original description"
			}
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				linked          = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}`
	createXksKeyConfigStr := fmt.Sprintf(createXksKeyConfig, createAlias)
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr + createXksKeyConfigStr

	// Update attempts to change description, alias (CM 2.23+), tags, and bypass_policy_lockout_safety_check -
	// all invalid when the key stays unlinked.
	invalidUpdateXksKeyConfig := `
		resource "ciphertrust_aws_xks_key" "unlinked_update_invalid" {
			aws_param = {
				# Placeholder for alias < invalid for CM < 2.23
				%s
				description = "changed description"
				tags = {
					Key1 = "Val1"
				}
			}
			bypass_policy_lockout_safety_check = true
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				linked          = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}`
	invalidUpdateXksKeyConfigStr := fmt.Sprintf(invalidUpdateXksKeyConfig, updateAlias)
	invalidUpdateConfigStr := awsConnectionResource + createKeyStoreConfigStr + invalidUpdateXksKeyConfigStr

	keyResource := "ciphertrust_aws_xks_key.unlinked_update_invalid"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "aws_param.description", "original description"),
				),
			},
			{
				Config: invalidUpdateConfigStr,
				// Expect a single "Invalid configuration for an unlinked key" error listing
				// aws_param.description, aws_param.tags, and bypass_policy_lockout_safety_check
				// (and aws_param.alias on CM 2.23+).
				ExpectError: regexp.MustCompile(
					`(?s)Invalid configuration for an unlinked key` +
						`.*aws_param\.description` +
						`.*aws_param\.tags` +
						`.*bypass_policy_lockout_safety_check`,
				),
			},
		},
	})
}

// TestCckmAWSXksLinkedOrUnlinkedKeyCreateModifyPlan verifies that ModifyPlan rejects attributes that
// cannot be set at creation time for any XKS key (linked or unlinked):
// more than one alias, enable_rotation, and enable_key = false.
// Note: aws_param.tags, key_policy, and bypass_policy_lockout_safety_check are valid when linked = true.
func TestCckmAWSXksLinkedOrUnlinkedKeyCreateModifyPlan(t *testing.T) {
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
					`(?s)Invalid configuration for a new XKS key` +
						`.*aws_param\.alias` +
						`.*enable_rotation` +
						`.*enable_key`,
				),
			},
		},
	})
}
