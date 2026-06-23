package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSDataSourceCustomKeyStore(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store-" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CIPHERTRUST_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}

	keyStoreResourceConfig := fmt.Sprintf(`
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = "%s"
			algorithm    = "AES"
			usage_mask   = local.cm_key_usage_mask
			unexportable = true
			undeletable  = true
			remove_from_state_on_destroy = true
		}
		resource "ciphertrust_aws_custom_keystore" "custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms_id  = ciphertrust_aws_kms.kms.id
			linked_state = false
			enable_success_audit_event = false
			local_hosted_params = {
				blocked = false
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param = {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "VPC_ENDPOINT_SERVICE"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
				key_store_password = "thequickbrownfox"
				xks_proxy_vpc_endpoint_service_name = "endpointservicename"
			}
		}`, cmKeyName, keyStoreName, proxyURIEndpoint)

	byName := `
		data "ciphertrust_aws_custom_keystore_list" "by_name" {
			filters = {
				name = ciphertrust_aws_custom_keystore.custom_keystore.name
			}
		}`

	byKmsID := `
		data "ciphertrust_aws_custom_keystore_list" "by_kms_id" {
			filters = {
				kms_id = ciphertrust_aws_kms.kms.id
			}
		}`

	keyStoreResourceName := "ciphertrust_aws_custom_keystore.custom_keystore"
	dsByName := "data.ciphertrust_aws_custom_keystore_list.by_name"
	dsByKmsID := "data.ciphertrust_aws_custom_keystore_list.by_kms_id"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Filter by name - should find exactly one match equal to our resource.
				Config: awsConnectionResource + keyStoreResourceConfig + byName,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "id"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", keyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "local_hosted_params.blocked", "false"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "local_hosted_params.max_credentials", "8"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "local_hosted_params.source_key_tier", "local"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.custom_key_store_type", "EXTERNAL_KEY_STORE"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.xks_proxy_connectivity", "VPC_ENDPOINT_SERVICE"),

					resource.TestCheckResourceAttr(dsByName, "matched", "1"),
					resource.TestCheckResourceAttr(dsByName, "custom_key_stores.#", "1"),
					resource.TestCheckResourceAttrPair(dsByName, "custom_key_stores.0.id", keyStoreResourceName, "id"),
					resource.TestCheckResourceAttrPair(dsByName, "custom_key_stores.0.name", keyStoreResourceName, "name"),
					resource.TestCheckResourceAttrPair(dsByName, "custom_key_stores.0.region", keyStoreResourceName, "region"),
					resource.TestCheckResourceAttrPair(dsByName, "custom_key_stores.0.kms_id", keyStoreResourceName, "kms_id"),
					resource.TestCheckResourceAttr(dsByName, "custom_key_stores.0.aws_param.custom_key_store_type", "EXTERNAL_KEY_STORE"),
					resource.TestCheckResourceAttr(dsByName, "custom_key_stores.0.aws_param.xks_proxy_connectivity", "VPC_ENDPOINT_SERVICE"),
					resource.TestCheckResourceAttr(dsByName, "custom_key_stores.0.local_hosted_params.blocked", "false"),
					resource.TestCheckResourceAttr(dsByName, "custom_key_stores.0.local_hosted_params.source_key_tier", "local"),
					resource.TestCheckResourceAttrSet(dsByName, "custom_key_stores.0.local_hosted_params.health_check_uri_path"),
				),
			},
			{
				// Filter by kms_id - should return at least the key store we created.
				Config: awsConnectionResource + keyStoreResourceConfig + byKmsID,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsByKmsID, "matched"),
					resource.TestCheckResourceAttrSet(dsByKmsID, "custom_key_stores.0.id"),
					resource.TestCheckResourceAttrSet(dsByKmsID, "custom_key_stores.0.kms_id"),
					resource.TestCheckResourceAttrSet(dsByKmsID, "custom_key_stores.0.name"),
					resource.TestCheckResourceAttr(dsByKmsID, "custom_key_stores.0.aws_param.custom_key_store_type", "EXTERNAL_KEY_STORE"),
				),
			},
		},
	})
}
