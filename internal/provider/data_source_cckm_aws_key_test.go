package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsKeyDataSource(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
		  alias  = [local.alias, "%s"]
		  kms    = ciphertrust_aws_kms.kms.id
		  region = ciphertrust_aws_kms.kms.regions[0]
		}`
	datasourceConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias       = [local.alias, "%s"]
			description = "Updated"
			kms         = ciphertrust_aws_kms.kms.id
			region      = ciphertrust_aws_kms.kms.regions[0]
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
		data "ciphertrust_aws_key" "by_cipertrust_key_id" {
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
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyConfig, alias),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(datasourceConfig, alias, alias, alias),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_key.by_alias_ex1", "key_id"),
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_key.by_alias_ex2", "key_id"),
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_key.by_aws_key_id", "key_id"),
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_key.by_id", "key_id"),
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_key.by_cipertrust_key_id", "key_id"),
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_key.by_key_id_and_region", "key_id"),
					resource.TestCheckResourceAttrPair(keyResource, "key_id", "data.ciphertrust_aws_key.by_key_id_region_and_alias", "key_id"),
				),
			},
		},
	})
}
