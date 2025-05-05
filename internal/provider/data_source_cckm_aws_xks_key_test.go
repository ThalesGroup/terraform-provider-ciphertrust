package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsDataSourceXksKey(t *testing.T) {

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
		resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
			name    = "%s"
			region  = ciphertrust_aws_kms.kms.regions[0]
			kms     = ciphertrust_aws_kms.kms.name
			linked_state = false
			local_hosted_params {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials = 8
				source_key_tier = "local"
			}
			aws_param {
				xks_proxy_uri_endpoint = "%s"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				custom_key_store_type = "EXTERNAL_KEY_STORE"
			}
		}`

	cmKeyName := "tf-cm-key-" + uuid.New().String()[:8]
	keyStoreName := "tf-custom-key-store" + uuid.New().String()[:8]
	proxyURIEndpoint := os.Getenv("CM_ADDRESS")
	createKeyStoreConfigStr := fmt.Sprintf(createKeyStoreConfig, cmKeyName, keyStoreName, proxyURIEndpoint)

	createXKSKeyConfig := `
		resource "ciphertrust_aws_xks_key" "xks_key" {
			alias        = [local.alias]
			local_hosted_params {
				custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
				blocked = false
				linked  = false
				source_key_id   = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier = "local"
			}
		}`
	createConfigStr := awsConnectionResource + createKeyStoreConfigStr + createXKSKeyConfig

	datasourceConfig := `
		data "ciphertrust_aws_xks_key" "by_id" {
			id = ciphertrust_aws_xks_key.xks_key.id
		}
		/*
		data "ciphertrust_aws_xks_key" "by_alias" {
			alias = [local.alias]
		}
		data "ciphertrust_aws_xks_key" "by_aws_key_id" {
			aws_key_id = ciphertrust_aws_xks_key.xks_key.aws_key_id
		}
		data "ciphertrust_aws_xks_key" "by_ciphertrust_key_id" {
			key_id = ciphertrust_aws_xks_key.xks_key.key_id
		}
		data "ciphertrust_aws_xks_key" "by_key_id_and_region" {
			aws_key_id = ciphertrust_aws_xks_key.xks_key.aws_key_id
			region     = ciphertrust_aws_xks_key.xks_key.region
		}
		data "ciphertrust_aws_xks_key" "by_key_id_region_and_alias" {
			alias = [local.alias]
			aws_key_id = ciphertrust_aws_xks_key.xks_key.aws_key_id
			region     = ciphertrust_aws_xks_key.xks_key.region
		}*/`
	dataSourceConfigStr := awsConnectionResource + createKeyStoreConfigStr + createXKSKeyConfig + datasourceConfig

	keyResource := "ciphertrust_aws_xks_key.xks_key"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "blocked", "false"),
					resource.TestCheckResourceAttr(keyResource, "linked", "false"),
				),
			},
			{
				Config: dataSourceConfigStr,
				Check: resource.ComposeTestCheckFunc(
					// Only this will work with an unlinked key
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_xks_key.by_id", "key_id"),
					//resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_xks_key.by_alias_ex1", "key_id"),
					//resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_xks_key.by_aws_key_id", "key_id"),
					//resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_xks_key.by_ciphertrust_key_id", "key_id"),
					//resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_xks_key.by_key_id_and_region", "key_id"),
					//resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_xks_key.by_key_id_region_and_alias", "key_id"),
				),
			},
		},
	})
}
