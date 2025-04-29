package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsKms(t *testing.T) {
	createKmsConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "TerraformTest"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id    = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection = ciphertrust_aws_connection.aws_connection.name
			name          = "TerraformTest"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[0],
				data.ciphertrust_aws_account_details.account_details.regions[1],
				data.ciphertrust_aws_account_details.account_details.regions[2]
			]
		}`
	updateKmsRegionsConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "TerraformTest"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id    = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection = ciphertrust_aws_connection.aws_connection.name
			name          = "TerraformTest"
			regions       = [data.ciphertrust_aws_account_details.account_details.regions[0]]
		}`
	updateKmsConnectionConfig := `
		resource "ciphertrust_aws_connection" "new_aws_connection" {
			name = "TerraformTest-UpdatedConnection"
		}
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "TerraformTest"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id    = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection = ciphertrust_aws_connection.new_aws_connection.name
			name          = "TerraformTest"
			regions       = [data.ciphertrust_aws_account_details.account_details.regions[0]]
		}`
	resourceName := "ciphertrust_aws_kms.kms"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createKmsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttrSet(resourceName, "aws_connection"),
					resource.TestCheckResourceAttr(resourceName, "name", "TerraformTest"),
					resource.TestCheckResourceAttrSet(resourceName, "regions.#"),
				),
			},
			{
				Config: updateKmsRegionsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "regions.#", "1"),
				),
			},
			{
				Config: updateKmsConnectionConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "aws_connection", "TerraformTest-UpdatedConnection"),
					resource.TestCheckResourceAttr(resourceName, "regions.#", "1"),
				),
			},
		},
	})
}
