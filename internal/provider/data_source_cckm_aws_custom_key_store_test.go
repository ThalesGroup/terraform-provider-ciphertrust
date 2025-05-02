package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsDataSourceCustomKeyStore(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
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
		resource "ciphertrust_aws_custom_keystore" "custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms     = ciphertrust_aws_kms.kms.name
			linked_state = false
			enable_success_audit_event = false
			local_hosted_params {
				blocked = false
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
				mtls_enabled = true
			}
			aws_param {
				xks_proxy_uri_endpoint = "%s"
				#xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				xks_proxy_connectivity = "VPC_ENDPOINT_SERVICE"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
				key_store_password = "thequickbrownfox"
				xks_proxy_vpc_endpoint_service_name = "endpointservicename"
			}
		}
		data "ciphertrust_aws_custom_keystore" "by_id" {
			id = ciphertrust_aws_custom_keystore.custom_keystore.id
		}`

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CM_ADDRESS")
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, proxyURIEndpoint)

	keyStoreResourceName := "ciphertrust_aws_custom_keystore.custom_keystore"
	dataSourceResourceName := "data.ciphertrust_aws_custom_keystore.by_id"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createKeyStoreConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(keyStoreResourceName, "id", dataSourceResourceName, "id"),
				),
			},
		},
	})
}
