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
			kms_id  = ciphertrust_aws_kms.kms.id
			linked_state = false
			connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
			enable_success_audit_event = %t
			local_hosted_params = {
				blocked = false
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param = {
				xks_proxy_uri_endpoint = "%s"
				#xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				xks_proxy_connectivity = "VPC_ENDPOINT_SERVICE"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
				key_store_password = "%s"
				xks_proxy_vpc_endpoint_service_name = "%s"
			}
			enable_credential_rotation = {
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
			kms_id  = ciphertrust_aws_kms.kms.id
			linked_state = false
			enable_success_audit_event = %t
			local_hosted_params = {
				blocked = false
				health_check_key_id = ciphertrust_cm_key.cm_aes_key_new.id
				max_credentials = %d
				source_key_tier = "local"
			}
			aws_param = {
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
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, false,
		proxyURIEndpoint, keyStorePassword, vpcEndpointServiceName)

	newCmKeyName := "tf-cm-key-update-" + uuid.New().String()[:8]
	newKeyStoreName := "tf-update-custom-key-store" + uuid.New().String()[:8]
	newProxyURIEndpoint := "https://192.168.8.134"
	if os.Getenv("CDSPAAS") == "true" {
		newProxyURIEndpoint = proxyURIEndpoint
	}
	newKeyStorePassword := "jumpedoversomething"
	updateKeyStoreConfigStr := fmt.Sprintf(updateKeyStoreConfig, newCmKeyName, newKeyStoreName,
		true, 8, newProxyURIEndpoint, newKeyStorePassword, "EXTERNAL_KEY_STORE")
	modifyPlanConfigStr := fmt.Sprintf(updateKeyStoreConfig, newCmKeyName, newKeyStoreName,
		true, 8, newProxyURIEndpoint, newKeyStorePassword, "AWS_CLOUDHSM")
	modifyPlanMaxCredentialsStr := fmt.Sprintf(updateKeyStoreConfig, newCmKeyName, newKeyStoreName,
		true, 2, newProxyURIEndpoint, newKeyStorePassword, "EXTERNAL_KEY_STORE")

	newCmKeyNameEx2 := "tf-cm-key-update-" + uuid.New().String()[:8]
	updateKeyStoreConfigStrEx2 := fmt.Sprintf(createKeyStoreConfig, newCmKeyNameEx2, keyStoreName, false,
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
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "kms_id"),
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "kms_name"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "enable_success_audit_event", "false"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", keyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.xks_proxy_uri_endpoint", proxyURIEndpoint),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.key_store_password", "thequickbrownfox"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.xks_proxy_connectivity", "VPC_ENDPOINT_SERVICE"),
					// The key store is created disconnected; connecting requires a live AWS endpoint and
					// cannot be exercised in automated tests.
					resource.TestCheckResourceAttr(keyStoreResourceName, "connect_disconnect_keystore", "DISCONNECT_KEYSTORE"),
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
					"access_key_id",                // credentials only returned on create POST, not on GET
					"secret_access_key",            // credentials only returned on create POST, not on GET
					"aws_param.key_store_password", // write-only; not returned by the API
					"enable_credential_rotation",   // not surfaced in GET response; cannot round-trip
					"updated_at",                   // timestamp; may differ between the import Read and the prior-state Read
				},
			},
			{
				Config: awsConnectionResource + updateKeyStoreConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "id"),
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "kms_id"),
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "kms_name"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "enable_success_audit_event", "true"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", newKeyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.xks_proxy_uri_endpoint", newProxyURIEndpoint),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.key_store_password", "jumpedoversomething"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.xks_proxy_connectivity", "PUBLIC_ENDPOINT"),
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "local_hosted_params.health_check_key_id"),
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
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "kms_id"),
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "kms_name"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "enable_success_audit_event", "false"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", keyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.xks_proxy_uri_endpoint", proxyURIEndpoint),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.key_store_password", "thequickbrownfox"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.xks_proxy_connectivity", "VPC_ENDPOINT_SERVICE"),
				),
			},
		},
	})
}

// TestCckmAWSCustomKeyStoreEmptyLocalHostedParams covers two cases:
//  1. local_hosted_params block entirely absent - the API rejects the request.
//  2. Empty local_hosted_params {} block - the API rejects the request
//     (e.g. max_credentials not provided / below minimum).
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
			kms_id = ciphertrust_aws_kms.kms.id
			aws_param = {
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}`
	// Step 2: empty local_hosted_params {} block - provider guard is satisfied but
	// the API rejects the request because no required fields (e.g. max_credentials) were set.
	emptyBlockConfig := `
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name   = "tf-test-empty-local-hosted-params"
			region = ciphertrust_aws_kms.kms.regions[0]
			kms_id = ciphertrust_aws_kms.kms.id
			aws_param = {
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
			local_hosted_params = {}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// API rejects the request when local_hosted_params is absent.
				Config:      awsConnectionResource + absentConfig,
				ExpectError: regexp.MustCompile(`Error creating AWS Custom Key Store`),
			},
			{
				// API rejects the request when local_hosted_params is empty (e.g. max_credentials < 2).
				Config:      awsConnectionResource + emptyBlockConfig,
				ExpectError: regexp.MustCompile(`Error creating AWS Custom Key Store`),
			},
		},
	})
}

func TestCckmAWSCustomKeyStoreEmptyAwsParams(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	// Step 1: aws_param block is entirely absent.
	absentConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = "%s"
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
			unexportable = true
			undeletable  = true
			remove_from_state_on_destroy = true
		}

		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "tf-test-no-aws-param"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms_id  = ciphertrust_aws_kms.kms.id
			local_hosted_params = {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
		}`
	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	resourceName := "ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore"
	createConfig := fmt.Sprintf(absentConfig, cmKeyName)
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Verify the resource is created successfully without an aws_param block.
				// The provider populates aws_param from the API response on Read, so the
				// attributes below confirm that the server auto-filled sensible defaults.
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					// Top-level attributes.
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "kms_id"),
					resource.TestCheckResourceAttrSet(resourceName, "kms_name"),
					resource.TestCheckResourceAttr(resourceName, "name", "tf-test-no-aws-param"),
					resource.TestCheckResourceAttr(resourceName, "cloud_name", "aws"),
					resource.TestCheckResourceAttr(resourceName, "connect_disconnect_keystore", "DISCONNECT_KEYSTORE"),
					resource.TestCheckResourceAttr(resourceName, "enable_success_audit_event", "false"),
					resource.TestCheckResourceAttr(resourceName, "linked_state", "false"),
					resource.TestCheckResourceAttr(resourceName, "type", "LOCAL"),
					resource.TestCheckResourceAttr(resourceName, "labels.%", "0"),
					// aws_param attributes - auto-populated by the server even though the
					// aws_param block was omitted from the config.
					resource.TestCheckResourceAttr(resourceName, "aws_param.custom_key_store_type", "EXTERNAL_KEY_STORE"),
					resource.TestCheckResourceAttr(resourceName, "aws_param.custom_key_store_name", "tf-test-no-aws-param"),
					resource.TestCheckResourceAttr(resourceName, "aws_param.connection_state", "DISCONNECTED"),
					resource.TestCheckResourceAttr(resourceName, "aws_param.xks_proxy_connectivity", "PUBLIC_ENDPOINT"),
					// Server generates the XKS proxy URI path from the resource ID.
					resource.TestCheckResourceAttrSet(resourceName, "aws_param.xks_proxy_uri_path"),
					// Write-only and unset fields are returned as empty strings.
					resource.TestCheckResourceAttr(resourceName, "aws_param.key_store_password", ""),
					resource.TestCheckResourceAttr(resourceName, "aws_param.xks_proxy_uri_endpoint", ""),
					resource.TestCheckResourceAttr(resourceName, "aws_param.cloud_hsm_cluster_id", ""),
					resource.TestCheckResourceAttr(resourceName, "aws_param.trust_anchor_certificate", ""),
					resource.TestCheckResourceAttr(resourceName, "aws_param.xks_proxy_vpc_endpoint_service_name", ""),
					// local_hosted_params attributes.
					resource.TestCheckResourceAttr(resourceName, "local_hosted_params.blocked", "false"),
					resource.TestCheckResourceAttr(resourceName, "local_hosted_params.max_credentials", "8"),
					resource.TestCheckResourceAttr(resourceName, "local_hosted_params.source_key_tier", "local"),
					resource.TestCheckResourceAttr(resourceName, "local_hosted_params.source_container_type", "local"),
					resource.TestCheckResourceAttr(resourceName, "local_hosted_params.linked_state", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "local_hosted_params.health_check_key_id"),
					resource.TestCheckResourceAttrSet(resourceName, "local_hosted_params.health_check_ciphertext"),
					resource.TestCheckResourceAttrSet(resourceName, "local_hosted_params.health_check_uri_path"),
				),
			},
		},
	})
}
