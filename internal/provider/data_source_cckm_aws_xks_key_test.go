package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSDataSourceXksKey(t *testing.T) {

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
	proxyURIEndpoint := os.Getenv("CM_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, proxyURIEndpoint)

	createXKSKeyConfig := `
		resource "ciphertrust_aws_xks_key" "xks_key" {
			aws_param = {
				alias = [local.alias]
			}
			local_hosted_params = {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				blocked = false
				linked  = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}`
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr + createXKSKeyConfig

	// Only by_name is exercisable for an unlinked key because alias and aws_key_id
	// are not populated until the key is linked.
	datasourceConfig := `
		data "ciphertrust_aws_xks_keys_list" "by_name" {
			filters = { "id" = ciphertrust_aws_xks_key.xks_key.id }
		}`
	dataSourceConfigStr := awsConnectionResource + createKeyStoreConfigStr + createXKSKeyConfig + datasourceConfig
	dsByName := "data.ciphertrust_aws_xks_keys_list.by_name"

	keyResource := "ciphertrust_aws_xks_key.xks_key"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "kms_id"),
					resource.TestCheckResourceAttrSet(keyResource, "custom_key_store_id"),
					resource.TestCheckResourceAttr(keyResource, "blocked", "false"),
					resource.TestCheckResourceAttr(keyResource, "linked", "false"),
					resource.TestCheckResourceAttr(keyResource, "key_source", "local"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.tags.%", "0"),
				),
			},
			{
				Config: dataSourceConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsByName, "matched", "1"),
					resource.TestCheckResourceAttrPair(keyResource, "blocked", dsByName, "keys.0.blocked"),
					resource.TestCheckResourceAttrPair(keyResource, "linked", dsByName, "keys.0.linked"),
					resource.TestCheckResourceAttrPair(keyResource, "kms_id", dsByName, "keys.0.kms_id"),

					resource.TestCheckResourceAttr(dsByName, "keys.0.labels.%", "0"),
					// aws_param block - alias and tags are empty for unlinked keys
					resource.TestCheckResourceAttr(dsByName, "keys.0.aws_param.alias.#", "0"),
					resource.TestCheckResourceAttr(dsByName, "keys.0.aws_param.tags.%", "0"),
				),
			},
		},
	})
}
