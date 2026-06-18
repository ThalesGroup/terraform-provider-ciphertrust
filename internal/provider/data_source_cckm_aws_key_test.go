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
		  alias  = [local.alias, "%s"]
		  kms    = ciphertrust_aws_kms.kms.id
		  region = ciphertrust_aws_kms.kms.regions[0]
          origin = "AWS_KMS"
          customer_master_key_spec = "SYMMETRIC_DEFAULT"
		}`
	datasourceConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias       = [local.alias, "%s"]
			description = "Updated"
			kms         = ciphertrust_aws_kms.kms.id
			region      = ciphertrust_aws_kms.kms.regions[0]
            origin      = "AWS_KMS"
            customer_master_key_spec = "SYMMETRIC_DEFAULT"
		}
		data "ciphertrust_aws_key" "by_alias_ex1" {
			alias = [local.alias]
		}
		data "ciphertrust_aws_key" "by_alias_ex2" {
			alias = ["%s"]
		}
		data "ciphertrust_aws_key" "by_aws_key_id" {
			aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
		}
		data "ciphertrust_aws_key" "by_id" {
			id = ciphertrust_aws_key.aws_key.id
		}
		data "ciphertrust_aws_key" "by_ciphertrust_key_id" {
			key_id = ciphertrust_aws_key.aws_key.key_id
		}
		data "ciphertrust_aws_key" "by_key_id_and_region" {
			aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
			region     = ciphertrust_aws_key.aws_key.region
		}
		data "ciphertrust_aws_key" "by_key_id_region_and_alias" {
			alias = ["%s"]
			aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
			region     = ciphertrust_aws_key.aws_key.region
		}`

	alias := awsKeyNamePrefix + uuid.New().String()[:8]
	keyResource := "ciphertrust_aws_key.aws_key"
	dataSourceByKeyIDAndRegion := "data.ciphertrust_aws_key.by_key_id_and_region"
	datSourceByKeyIDAndAlias := "data.ciphertrust_aws_key.by_key_id_region_and_alias"
	dataSourceByAwsKeyID := "data.ciphertrust_aws_key.by_aws_key_id"
	dataSourceByCCKMKeyID := "data.ciphertrust_aws_key.by_ciphertrust_key_id"
	dataSouceByResourceID := "data.ciphertrust_aws_key.by_id"
	dataSourceByFirstAlias := "data.ciphertrust_aws_key.by_alias_ex1"
	dataSourceBySecondAlias := "data.ciphertrust_aws_key.by_alias_ex2"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, alias),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "arn"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_key_id"),
					resource.TestCheckResourceAttrSet(keyResource, "key_id"),
					resource.TestCheckResourceAttr(keyResource, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(keyResource, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(keyResource, "origin", "AWS_KMS"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(datasourceConfig, alias, alias, alias),
				Check: resource.ComposeTestCheckFunc(

					// alias-only filters: just verify the correct key was found
					resource.TestCheckResourceAttrPair(keyResource, "key_id", dataSourceByFirstAlias, "key_id"),
					resource.TestCheckResourceAttrPair(keyResource, "key_id", dataSourceBySecondAlias, "key_id"),

					// by_aws_key_id: globally unique filter - full attribute verification
					resource.TestCheckResourceAttrPair(keyResource, "key_id", dataSourceByAwsKeyID, "key_id"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "description", "Updated"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "enabled", "true"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "key_state", "Enabled"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "key_usage", "ENCRYPT_DECRYPT"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "origin", "AWS_KMS"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "auto_rotate", "false"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "tags.%", "0"),
					resource.TestCheckResourceAttr(dataSourceByAwsKeyID, "alias.#", "2"),
					resource.TestCheckResourceAttrSet(dataSourceByAwsKeyID, "arn"),
					resource.TestCheckResourceAttrPair(dataSourceByAwsKeyID, "region", keyResource, "region"),

					// by_id: composite region\kid filter - unique, verify core attributes
					resource.TestCheckResourceAttrPair(keyResource, "key_id", dataSouceByResourceID, "key_id"),
					resource.TestCheckResourceAttr(dataSouceByResourceID, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(dataSouceByResourceID, "description", "Updated"),
					resource.TestCheckResourceAttr(dataSouceByResourceID, "key_state", "Enabled"),

					// by_ciphertrust_key_id: CM UUID filter - unique, verify description and kms_id
					resource.TestCheckResourceAttrPair(keyResource, "key_id", dataSourceByCCKMKeyID, "key_id"),
					resource.TestCheckResourceAttr(dataSourceByCCKMKeyID, "description", "Updated"),
					resource.TestCheckResourceAttrPair(dataSourceByCCKMKeyID, "kms_id", "ciphertrust_aws_kms.kms", "id"),

					// by_key_id_and_region: aws_key_id+region filter - unique, verify core attributes
					resource.TestCheckResourceAttrPair(keyResource, "key_id", dataSourceByKeyIDAndRegion, "key_id"),
					resource.TestCheckResourceAttr(dataSourceByKeyIDAndRegion, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(dataSourceByKeyIDAndRegion, "key_state", "Enabled"),

					// by_key_id_region_and_alias: aws_key_id+alias+region filter - unique, verify core attributes
					resource.TestCheckResourceAttrPair(keyResource, "key_id", datSourceByKeyIDAndAlias, "key_id"),
					resource.TestCheckResourceAttr(datSourceByKeyIDAndAlias, "customer_master_key_spec", "SYMMETRIC_DEFAULT"),
					resource.TestCheckResourceAttr(datSourceByKeyIDAndAlias, "key_state", "Enabled"),
				),
			},
		},
	})
}
