package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSCustomKeyStoreUnlinked(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	schedulerConfig := `
		resource "ciphertrust_scheduler" "credential_rotation" {
			cckm_xks_credential_rotation_params = {
				cloud_name       = "aws"
			}
			name       = "%s"
			operation  = "cckm_xks_credential_rotation"
			run_at     = "0 9 * * sat"
		}`
	schedulerConfigStr := fmt.Sprintf(schedulerConfig, "tf-"+uuid.NewString()[:8])
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
			#kms     = ciphertrust_aws_kms.kms.name
			kms     = ciphertrust_aws_kms.kms.id
			linked_state = false
			connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
			enable_success_audit_event = %t
			local_hosted_params {
				blocked = false
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
				mtls_enabled = %t
			}
			aws_param {
				xks_proxy_uri_endpoint = "%s"
				#xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				xks_proxy_connectivity = "VPC_ENDPOINT_SERVICE"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
				key_store_password = "%s"
				xks_proxy_vpc_endpoint_service_name = "%s"
			}
			enable_credential_rotation {
				job_config_id = ciphertrust_scheduler.credential_rotation.id
			}
		}`
	updateKeyStoreConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key_new" {
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
			#kms     = ciphertrust_aws_kms.kms.name
			kms     = ciphertrust_aws_kms.kms.id
			linked_state = false
			enable_success_audit_event = %t
			local_hosted_params {
				blocked = false
				health_check_key_id = ciphertrust_cm_key.cm_aes_key_new.id
				max_credentials = %d
				source_key_tier = "local"
				mtls_enabled = %t
			}
			aws_param {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				key_store_password = "%s"
				custom_key_store_type = "%s"
			}
		}`

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CM_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}
	keyStorePassword := "thequickbrownfox"
	vpcEndpointServiceName := "testEndpointServiceName"
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, false, true,
		proxyURIEndpoint, keyStorePassword, vpcEndpointServiceName)

	newCmKeyName := "tf-cm-key-update-" + uuid.New().String()[:8]
	newKeyStoreName := "tf-update-custom-key-store" + uuid.New().String()[:8]
	newProxyURIEndpoint := "https://192.168.8.134"
	if os.Getenv("CDSPAAS") == "true" {
		newProxyURIEndpoint = proxyURIEndpoint
	}
	newKeyStorePassword := "jumpedoversomething"
	updateKeyStoreConfigStr := fmt.Sprintf(updateKeyStoreConfig, newCmKeyName, newKeyStoreName,
		true, 8, false, newProxyURIEndpoint, newKeyStorePassword, "EXTERNAL_KEY_STORE")
	modifyPlanConfigStr := fmt.Sprintf(updateKeyStoreConfig, newCmKeyName, newKeyStoreName,
		true, 8, false, newProxyURIEndpoint, newKeyStorePassword, "AWS_CLOUDHSM")
	modifyPlanMaxCredentialsStr := fmt.Sprintf(updateKeyStoreConfig, newCmKeyName, newKeyStoreName,
		true, 2, false, newProxyURIEndpoint, newKeyStorePassword, "EXTERNAL_KEY_STORE")

	newCmKeyNameEx2 := "tf-cm-key-update-" + uuid.New().String()[:8]
	updateKeyStoreConfigStrEx2 := fmt.Sprintf(createKeyStoreConfig, newCmKeyNameEx2, keyStoreName, false, true,
		proxyURIEndpoint, keyStorePassword, vpcEndpointServiceName)

	keyStoreResourceName := "ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + schedulerConfigStr + createKeyStoreConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "id"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "enable_success_audit_event", "false"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", keyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_uri_endpoint", proxyURIEndpoint),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.key_store_password", "thequickbrownfox"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_connectivity", "VPC_ENDPOINT_SERVICE"),
					// The key store is created disconnected; connecting requires a live AWS endpoint and
					// cannot be exercised in automated tests.
					resource.TestCheckResourceAttr(keyStoreResourceName, "connect_disconnect_keystore", "DISCONNECT_KEYSTORE"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "local_hosted_params.0.mtls_enabled", "true"),
					// enable_credential_rotation is silently skipped for unlinked key stores (linked_state = false);
					// the block is accepted in config but the API call is gated on linked_state.
					// Labels are unrelated and checked separately below.
					resource.TestCheckResourceAttr(keyStoreResourceName, "labels.%", "0"),
				),
			},
			{
				ResourceName:      keyStoreResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"aws_param.0.key_store_password", // write-only; not returned by the API
					"enable_credential_rotation",     // not surfaced in GET response; cannot round-trip
					// kms: the plan may supply a name or ID, but import always returns the ID from the
					// API response. setCustomKeyStoreState only overwrites plan.KMS when it is empty,
					// so the value after import may differ from the planned value causing a spurious diff.
					"kms",
					"updated_at", // timestamp; may differ between the import Read and the prior-state Read
				},
			},
			{
				Config: awsConnectionResource + updateKeyStoreConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "id"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "enable_success_audit_event", "true"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", newKeyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_uri_endpoint", newProxyURIEndpoint),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.key_store_password", "jumpedoversomething"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_connectivity", "PUBLIC_ENDPOINT"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "local_hosted_params.0.mtls_enabled", "false"),
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "local_hosted_params.0.health_check_key_id"),
				),
			},
			{
				// Verify ModifyPlan fires an error when aws_param.custom_key_store_type is changed.
				Config:      awsConnectionResource + modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// Verify ModifyPlan fires an error when local_hosted_params.max_credentials is changed.
				Config:      awsConnectionResource + modifyPlanMaxCredentialsStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				Config: awsConnectionResource + schedulerConfigStr + updateKeyStoreConfigStrEx2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "id"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "enable_success_audit_event", "false"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", keyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_uri_endpoint", proxyURIEndpoint),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.key_store_password", "thequickbrownfox"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_connectivity", "VPC_ENDPOINT_SERVICE"),
				),
			},
		},
	})
}

// TestCckmAWSCustomKeyStoreEmptyLocalHostedParams covers two cases:
//  1. local_hosted_params block entirely absent - provider guard fires immediately.
//  2. Empty local_hosted_params {} block - passes the provider guard but the API
//     rejects the request (e.g. max_credentials not provided / below minimum).
func TestCckmAWSCustomKeyStoreEmptyLocalHostedParams(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	// Step 1: local_hosted_params block is entirely absent.
	absentConfig := `
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name   = "tf-test-no-local-hosted-params"
			region = ciphertrust_aws_kms.kms.regions[0]
			kms    = ciphertrust_aws_kms.kms.id
			aws_param {
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}`
	// Step 2: empty local_hosted_params {} block - provider guard is satisfied but
	// the API rejects the request because no required fields (e.g. max_credentials) were set.
	emptyBlockConfig := `
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name   = "tf-test-empty-local-hosted-params"
			region = ciphertrust_aws_kms.kms.regions[0]
			kms    = ciphertrust_aws_kms.kms.id
			aws_param {
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
			local_hosted_params {}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Provider guard fires - no API call made.
				Config:      awsConnectionResource + absentConfig,
				ExpectError: regexp.MustCompile(`Missing local_hosted_params block`),
			},
			{
				// Provider guard is satisfied; API rejects (e.g. max_credentials < 2).
				Config:      awsConnectionResource + emptyBlockConfig,
				ExpectError: regexp.MustCompile(`Error creating AWS Custom Key Store`),
			},
		},
	})
}

// TestCckmAWSCustomKeyStoreEmptyAwsParams covers two cases:
//  1. aws_param block entirely absent - provider guard fires immediately.
//  2. Empty aws_param {} block - Terraform schema validation rejects it because
//     the required custom_key_store_type argument is missing.
func TestCckmAWSCustomKeyStoreEmptyAwsParams(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	// Step 1: aws_param block is entirely absent.
	absentConfig := `
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "tf-test-no-aws-param"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms     = ciphertrust_aws_kms.kms.id
		}`
	// Step 2: empty aws_param {} block - schema validation rejects it because
	// custom_key_store_type is a required argument inside the block.
	emptyAwsParamConfig := `
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "tf-test-empty-aws-param"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms     = ciphertrust_aws_kms.kms.id
			aws_param {}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Schema validation fires because custom_key_store_type is required.
				// This step is first so it is NOT the last config used by the post-test
				// destroy phase (aws_param {} fails schema validation even for destroy).
				Config:      awsConnectionResource + emptyAwsParamConfig,
				ExpectError: regexp.MustCompile(`Missing required argument`),
			},
			{
				// Provider guard fires - no API call made. This config is last so it is
				// used by the post-test destroy; it passes schema validation and the
				// destroy is a no-op because no state was ever created.
				Config:      awsConnectionResource + absentConfig,
				ExpectError: regexp.MustCompile(`Missing aws_param block`),
			},
		},
	})
}
