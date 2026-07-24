// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmAWSCustomKeyStoreCreateUpdate verifies create and update behaviour for
// a LOCAL (unlinked XKS) custom key store.
//
// Steps covered:
//  1. Create - unblocked, audit disabled.
//  2. Import state.
//  3. Update - block and enable audit event.
//  4. Update - unblock and disable audit event.
//  5. Create - blocked=true at creation time (new resource name; unlinked key store).
//  6. Cleanup - remove the blocked key store created in step 5.
//  7. PlanOnly error - custom_key_store_type is immutable after creation.
//  8. PlanOnly error - max_credentials is immutable after creation.
//  9. PlanOnly error - connect_disconnect_keystore cannot be set at creation time.
//  10. PlanOnly error - enable_credential_rotation cannot be set at creation time.
//
// Note: attaching a credential-rotation scheduler (enable_credential_rotation) requires
// the keystore to be linked to AWS, which is not possible in automated tests.
func TestCckmAWSCustomKeyStoreCreateUpdate(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-cks-" + uuid.New().String()[:8]
	keystoreResourceName := "ciphertrust_aws_custom_keystore.keystore"

	cmKeyResource := fmt.Sprintf(`
	resource "ciphertrust_cm_key" "cm_key" {
		name                         = "%s"
		algorithm                    = "AES"
		usage_mask                   = local.cm_key_usage_mask
		remove_from_state_on_destroy = true
	}`, cmKeyName)

	// Base config: unblocked, audit disabled, no aws_param, no scheduler.
	baseConfig := cmKeyResource + fmt.Sprintf(`
	resource "ciphertrust_aws_custom_keystore" "keystore" {
		name                       = "%s"
		region                     = ciphertrust_aws_kms.kms.regions[0]
		kms_id                     = ciphertrust_aws_kms.kms.id
		enable_success_audit_event = false
		local_hosted_params = {
			health_check_key_id = ciphertrust_cm_key.cm_key.id
			max_credentials     = 4
			source_key_tier     = "local"
		}
	}`, keyStoreName)

	// blocked=true, audit=true.
	blockedConfig := cmKeyResource + fmt.Sprintf(`
	resource "ciphertrust_aws_custom_keystore" "keystore" {
		name                       = "%s"
		region                     = ciphertrust_aws_kms.kms.regions[0]
		kms_id                     = ciphertrust_aws_kms.kms.id
		enable_success_audit_event = true
		local_hosted_params = {
			blocked             = true
			health_check_key_id = ciphertrust_cm_key.cm_key.id
			max_credentials     = 4
			source_key_tier     = "local"
		}
	}`, keyStoreName)

	// PlanOnly: changing custom_key_store_type on an existing resource - immutable.
	immutableTypeConfig := cmKeyResource + fmt.Sprintf(`
	resource "ciphertrust_aws_custom_keystore" "keystore" {
		name                       = "%s"
		region                     = ciphertrust_aws_kms.kms.regions[0]
		kms_id                     = ciphertrust_aws_kms.kms.id
		enable_success_audit_event = false
		local_hosted_params = {
			health_check_key_id = ciphertrust_cm_key.cm_key.id
			max_credentials     = 4
			source_key_tier     = "local"
		}
		aws_param = {
			custom_key_store_type = "AWS_CLOUDHSM"
		}
	}`, keyStoreName)

	// PlanOnly: changing max_credentials on an existing resource - immutable.
	immutableMaxCredsConfig := cmKeyResource + fmt.Sprintf(`
	resource "ciphertrust_aws_custom_keystore" "keystore" {
		name                       = "%s"
		region                     = ciphertrust_aws_kms.kms.regions[0]
		kms_id                     = ciphertrust_aws_kms.kms.id
		enable_success_audit_event = false
		local_hosted_params = {
			health_check_key_id = ciphertrust_cm_key.cm_key.id
			max_credentials     = 2
			source_key_tier     = "local"
		}
	}`, keyStoreName)

	// Config: create a second key store with blocked=true at creation time.
	// Uses a distinct resource name so Terraform plans a fresh create.
	createBlockedConfig := cmKeyResource + fmt.Sprintf(`
	resource "ciphertrust_aws_custom_keystore" "keystore" {
		name                       = "%s"
		region                     = ciphertrust_aws_kms.kms.regions[0]
		kms_id                     = ciphertrust_aws_kms.kms.id
		enable_success_audit_event = false
		local_hosted_params = {
			health_check_key_id = ciphertrust_cm_key.cm_key.id
			max_credentials     = 4
			source_key_tier     = "local"
		}
	}
	resource "ciphertrust_aws_custom_keystore" "keystore_blocked" {
		name   = "%s-blocked"
		region = ciphertrust_aws_kms.kms.regions[0]
		kms_id = ciphertrust_aws_kms.kms.id
		local_hosted_params = {
			blocked             = true
			health_check_key_id = ciphertrust_cm_key.cm_key.id
			max_credentials     = 4
			source_key_tier     = "local"
		}
	}`, keyStoreName, keyStoreName)

	// PlanOnly: connect_disconnect_keystore at create time (new resource, never in state).
	createConnectConfig := `
	resource "ciphertrust_aws_custom_keystore" "test_create_connect" {
		name                        = "tf-test-connect-create"
		region                      = ciphertrust_aws_kms.kms.regions[0]
		kms_id                      = ciphertrust_aws_kms.kms.id
		connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
		local_hosted_params = {
			max_credentials = 4
			source_key_tier = "local"
		}
	}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create unblocked with audit disabled.
			{
				Config: awsConnectionResource + baseConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keystoreResourceName, "id"),
					resource.TestCheckResourceAttrSet(keystoreResourceName, "kms_id"),
					resource.TestCheckResourceAttr(keystoreResourceName, "local_hosted_params.blocked", "false"),
					resource.TestCheckResourceAttr(keystoreResourceName, "enable_success_audit_event", "false"),
				),
			},
			// Step 2: import state.
			{
				ResourceName:      keystoreResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"aws_param.key_store_password", // write-only; not returned by the API
					"enable_credential_rotation",   // not surfaced in GET response; cannot round-trip
					"updated_at",                   // timestamp; may differ between import Read and prior-state Read
				},
			},
			// Step 3: block the key store and enable the audit event.
			{
				Config: awsConnectionResource + blockedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keystoreResourceName, "local_hosted_params.blocked", "true"),
					resource.TestCheckResourceAttr(keystoreResourceName, "enable_success_audit_event", "true"),
				),
			},
			// Step 4: unblock the key store and disable the audit event.
			{
				Config: awsConnectionResource + baseConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keystoreResourceName, "local_hosted_params.blocked", "false"),
					resource.TestCheckResourceAttr(keystoreResourceName, "enable_success_audit_event", "false"),
				),
			},
			// Step 5: create a second key store with blocked=true at creation time.
			// Verifies that the API accepts blocked=true on an unlinked key store at creation.
			{
				Config: awsConnectionResource + createBlockedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_aws_custom_keystore.keystore_blocked", "id"),
					resource.TestCheckResourceAttr("ciphertrust_aws_custom_keystore.keystore_blocked", "local_hosted_params.blocked", "true"),
				),
			},
			// Step 6: clean up the blocked key store so it is not in state for the PlanOnly steps.
			{
				Config: awsConnectionResource + baseConfig,
			},
			// Step 7: verify ModifyPlan rejects custom_key_store_type change (immutable).
			{
				Config:      awsConnectionResource + immutableTypeConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			// Step 8: verify ModifyPlan rejects max_credentials change (immutable).
			{
				Config:      awsConnectionResource + immutableMaxCredsConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			// Step 9: verify ModifyPlan rejects connect_disconnect_keystore at creation time.
			// The resource name is new so Terraform plans a create, triggering the guard.
			{
				Config:      awsConnectionResource + baseConfig + createConnectConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Cannot connect or disconnect a key store at creation time`),
			},
			// Step 10: verify ModifyPlan rejects enable_credential_rotation at creation time.
			// The resource name is new so Terraform plans a create, triggering the guard.
			{
				Config: awsConnectionResource + baseConfig + `
					resource "ciphertrust_aws_custom_keystore" "test_create_cred_rotation" {
						name   = "tf-test-cred-rotation-create"
						region = ciphertrust_aws_kms.kms.regions[0]
						kms_id = ciphertrust_aws_kms.kms.id
						local_hosted_params = {
							max_credentials = 4
							source_key_tier = "local"
						}
						enable_credential_rotation = {
							job_config_id = "00000000-0000-0000-0000-000000000000"
						}
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Cannot enable credential rotation at creation time`),
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
	createConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = "%s"
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
			remove_from_state_on_destroy = true
		}

		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "tf-test-no-aws-param"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms_id  = ciphertrust_aws_kms.kms.id
			enable_success_audit_event = %s
			local_hosted_params = {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
		}`

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	resourceName := "ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore"
	createConfigStr := fmt.Sprintf(createConfig, cmKeyName, "false")
	updateConfigStr := fmt.Sprintf(createConfig, cmKeyName, "true")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Verify the resource is created successfully without an aws_param block.
				// The provider populates aws_param from the API response on Read, so the
				// attributes below confirm that the server auto-filled sensible defaults.
				Config: awsConnectionResource + createConfigStr,
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
			{
				// Verify the resource is created successfully without an aws_param block.
				// The provider populates aws_param from the API response on Read, so the
				// attributes below confirm that the server auto-filled sensible defaults.
				Config: awsConnectionResource + updateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					// Top-level attributes.
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "kms_id"),
					resource.TestCheckResourceAttrSet(resourceName, "kms_name"),
					resource.TestCheckResourceAttr(resourceName, "name", "tf-test-no-aws-param"),
					resource.TestCheckResourceAttr(resourceName, "cloud_name", "aws"),
					resource.TestCheckResourceAttr(resourceName, "connect_disconnect_keystore", "DISCONNECT_KEYSTORE"),
					resource.TestCheckResourceAttr(resourceName, "enable_success_audit_event", "true"),
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
