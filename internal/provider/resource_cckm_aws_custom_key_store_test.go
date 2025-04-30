package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsCustomKeyStoreUnlinked(t *testing.T) {
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
			usage_mask   = 60
			unexportable = true
			undeletable  = true
			remove_from_state_on_destroy = true
		}
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms     = ciphertrust_aws_kms.kms.name
			linked_state = false
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
		}`
	updateKeyStoreConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key_new" {
			name         = "%s"
			algorithm    = "AES"
			usage_mask   = 60
			unexportable = true
			undeletable  = true
			remove_from_state_on_destroy = true
		}
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms     = ciphertrust_aws_kms.kms.name
			linked_state = false
			enable_success_audit_event = %t
			local_hosted_params {
				blocked = false
				health_check_key_id = ciphertrust_cm_key.cm_aes_key_new.id
				max_credentials = 8
				source_key_tier = "local"
				mtls_enabled = %t
			}
			aws_param {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
				key_store_password = "%s"
			}
		}`

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CM_ADDRESS")
	keyStorePassword := "thequickbrownfox"
	vpcEndpointServiceName := "testEndpointServiceName"
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, false, true,
		proxyURIEndpoint, keyStorePassword, vpcEndpointServiceName)

	newCmKeyName := "tf-cm-key-update-" + uuid.New().String()[:8]
	newKeyStoreName := "tf-update-custom-key-store" + uuid.New().String()[:8]
	newProxyURIEndpoint := "https://192.168.8.134"
	newKeyStorePassword := "jumpedoversomething"
	updateKeyStoreConfigStr := fmt.Sprintf(updateKeyStoreConfig, newCmKeyName, newKeyStoreName, true, false,
		newProxyURIEndpoint, newKeyStorePassword)

	newCmKeyNameEx2 := "tf-cm-key-update-" + uuid.New().String()[:8]
	updateKeyStoreConfigStrEx2 := fmt.Sprintf(createKeyStoreConfig, newCmKeyNameEx2, keyStoreName, false, true,
		proxyURIEndpoint, keyStorePassword, vpcEndpointServiceName)

	keyStoreResourceName := "ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createKeyStoreConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyStoreResourceName, "id"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "enable_success_audit_event", "false"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "name", keyStoreName),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_uri_endpoint", proxyURIEndpoint),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.key_store_password", "thequickbrownfox"),
					resource.TestCheckResourceAttr(keyStoreResourceName, "aws_param.0.xks_proxy_connectivity", "VPC_ENDPOINT_SERVICE"),
				),
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
				),
			},
			{
				Config: awsConnectionResource + updateKeyStoreConfigStrEx2,
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
