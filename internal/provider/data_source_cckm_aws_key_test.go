package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSDataSourceKey(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
		  aws_param = {
		    alias  = [local.alias, "%s"]
		    customer_master_key_spec = "SYMMETRIC_DEFAULT"
		  }
		  kms_id = ciphertrust_aws_kms.kms.id
		  region = ciphertrust_aws_kms.kms.regions[0]
		}`
	datasourceConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			aws_param = {
				alias       = [local.alias, "%s"]
				description = "Updated"
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
			}
			kms_id      = ciphertrust_aws_kms.kms.id
			region      = ciphertrust_aws_kms.kms.regions[0]
		}
		data "ciphertrust_aws_keys_list" "by_alias" {
			filters = { "alias" = local.alias }
		}
		data "ciphertrust_aws_keys_list" "by_aws_key_id" {
			filters = { "keyid" = ciphertrust_aws_key.aws_key.aws_param.key_id }
		}
		data "ciphertrust_aws_keys_list" "by_ciphertrust_key_id" {
			filters = { "id" = ciphertrust_aws_key.aws_key.id }
		}
		data "ciphertrust_aws_keys_list" "by_key_id_and_region" {
			filters = {
				"keyid"  = ciphertrust_aws_key.aws_key.aws_param.key_id
				"region" = ciphertrust_aws_key.aws_key.region
			}
		}`

	alias := awsKeyNamePrefix + uuid.New().String()[:8]
	keyResource := "ciphertrust_aws_key.aws_key"
	dsByAwsKeyID := "data.ciphertrust_aws_keys_list.by_aws_key_id"
	dsByAwsKeyIDAndRegion := "data.ciphertrust_aws_keys_list.by_key_id_and_region"
	dsByKeyID := "data.ciphertrust_aws_keys_list.by_ciphertrust_key_id"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, alias),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.key_id"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.origin", "AWS_KMS"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(datasourceConfig, alias),
				Check: resource.ComposeTestCheckFunc(
					// by_alias: verify the correct key was found
					resource.TestCheckResourceAttr("data.ciphertrust_aws_keys_list.by_alias", "matched", "1"),
					resource.TestCheckResourceAttrPair(keyResource, "id", "data.ciphertrust_aws_keys_list.by_alias", "keys.0.key_id"),

					// by_aws_key_id: globally unique filter - verify core attributes
					resource.TestCheckResourceAttr(dsByAwsKeyID, "matched", "1"),
					resource.TestCheckResourceAttrPair(keyResource, "id", dsByAwsKeyID, "keys.0.key_id"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.auto_rotate", "false"),
					// aws_param block
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.description", "Updated"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.enabled", "true"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.multi_region", "false"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.tags.%", "0"),
					resource.TestCheckResourceAttr(dsByAwsKeyID, "keys.0.aws_param.alias.#", "2"),
					resource.TestCheckResourceAttrSet(dsByAwsKeyID, "keys.0.aws_param.arn"),

					// by_ciphertrust_key_id: CM UUID filter
					resource.TestCheckResourceAttr(dsByKeyID, "matched", "1"),
					resource.TestCheckResourceAttrPair(keyResource, "id", dsByKeyID, "keys.0.key_id"),
					resource.TestCheckResourceAttr(dsByKeyID, "keys.0.aws_param.description", "Updated"),

					// by_key_id_and_region: aws_key_id+region filter
					resource.TestCheckResourceAttr(dsByAwsKeyIDAndRegion, "matched", "1"),
					resource.TestCheckResourceAttrPair(keyResource, "id", dsByAwsKeyIDAndRegion, "keys.0.key_id"),
					resource.TestCheckResourceAttr(dsByAwsKeyIDAndRegion, "keys.0.aws_param.customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(dsByAwsKeyIDAndRegion, "keys.0.aws_param.key_state", "Enabled"),
				),
			},
		},
	})
}
