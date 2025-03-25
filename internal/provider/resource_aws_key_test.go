package provider

import (
	"fmt"
	guuid "github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"os"
	"testing"
)

const (
	awsKeyNamePrefix    = "tf-aws-"
	awsPolicyUserPrefix = "arn:aws:iam::556782317223:user/"
	awsPolicyRolePrefix = "arn:aws:iam::556782317223:role/"
)

var (
	awsKeyUsers  = []string{"cdua-terraform-user", "rpandita"}
	awsKeyRoles  = []string{"cckm-role-with-ext-id", "DATAENG_ROLE"}
	awsKeyPolicy = `{
	"Id": "key-consolepolicy-3",
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "Enable IAM UserName Permissions",
		"Effect": "Allow",
		"Principal": {
			"AWS": "arn:aws:iam::556782317223:root"
		},
		"Action": "kms:*",
		"Resource": "*"
	}]
}`
)

func initCckmAwsTest() (string, bool) {
	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if awsAccessKeyID == "" || awsSecretAccessKey == "" {
		return "", false
	}
	awsConfig := `
		provider "ciphertrust" {}
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "TerraformTest"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection  = ciphertrust_aws_connection.aws_connection.id
			name           = "TerraformTest"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[0],
				data.ciphertrust_aws_account_details.account_details.regions[1],
				data.ciphertrust_aws_account_details.account_details.regions[2],
				"us-west-1",
			]
		}
		locals {
			alias   = "%s"
		}`
	awsConnectionResource := fmt.Sprintf(awsConfig, "TF-Test-"+guuid.New().String())
	return awsConnectionResource, true
}

func TestCckmAwsKeyDetailed(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createKeyWithExtrasConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias        = [local.alias, "%s", "%s"]
			customer_master_key_spec = "RSA_4096"
			description  = "CreateKeyWithExtras original description"
			enable_key   = false
			key_policy {
				key_admins  = ["%s"]
				key_users   = ["%s"]
				key_admins_roles  = ["%s"]
				key_users_roles   = ["%s"]
			}
			key_usage    = "SIGN_VERIFY"
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey1 = "CreateKeyWithExtras_TagValue1"
				TagKey2 = "CreateKeyWithExtras_TagValue2"
			}
		}`
	updateKeyConfig := `
		resource "ciphertrust_aws_key" "aws_key" {
			alias        = [local.alias]
			customer_master_key_spec = "RSA_4096"
			description  = "CreateKeyWithExtras new description"
			enable_key   = true
			key_policy {
				policy = <<-EOT
					%s
				EOT
			}
			key_usage = "SIGN_VERIFY"
			kms       = ciphertrust_aws_kms.kms.id
			region    = ciphertrust_aws_kms.kms.regions[0]
			tags = {
				TagKey3 = "CreateKeyWithExtras_TagValue3"
				TagKey1 = "CreateKeyWithExtras_TagValue1"
				TagKey2 = "CreateKeyWithExtras_TagValue2"
			}
		}`
	var aliasList []string
	aliasList = append(aliasList, awsKeyNamePrefix+guuid.New().String())
	aliasList = append(aliasList, awsKeyNamePrefix+guuid.New().String())
	resourceName := "ciphertrust_aws_key.aws_key"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyWithExtrasConfig, aliasList[0], aliasList[1],
					awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "3"),
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "customer_master_key_spec", "RSA_4096"),
					resource.TestCheckResourceAttr(resourceName, "description", "CreateKeyWithExtras original description"),
					resource.TestCheckResourceAttr(resourceName, "enable_key", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "key_id"),
					resource.TestCheckResourceAttr(resourceName, "key_usage", "SIGN_VERIFY"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "CreateKeyWithExtras_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "CreateKeyWithExtras_TagValue2"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(updateKeyConfig, awsKeyPolicy),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "description", "CreateKeyWithExtras new description"),
					resource.TestCheckResourceAttr(resourceName, "enable_key", "true"),
					resource.TestCheckResourceAttr(resourceName, "key_users.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_admin.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_admin_roles.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "CreateKeyWithExtras_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "CreateKeyWithExtras_TagValue2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey3", "CreateKeyWithExtras_TagValue3"),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
			{
				Config: awsConnectionResource + fmt.Sprintf(createKeyWithExtrasConfig, aliasList[0], aliasList[1],
					awsKeyUsers[0], awsKeyUsers[1], awsKeyRoles[0], awsKeyRoles[1]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "alias.#", "3"),
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "customer_master_key_spec", "RSA_4096"),
					resource.TestCheckResourceAttr(resourceName, "description", "CreateKeyWithExtras original description"),
					resource.TestCheckResourceAttr(resourceName, "enable_key", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "key_id"),
					resource.TestCheckResourceAttr(resourceName, "key_usage", "SIGN_VERIFY"),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey1", "CreateKeyWithExtras_TagValue1"),
					resource.TestCheckResourceAttr(resourceName, "tags.TagKey2", "CreateKeyWithExtras_TagValue2"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.0", awsPolicyUserPrefix+awsKeyUsers[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users.0", awsPolicyUserPrefix+awsKeyUsers[1]),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.0", awsPolicyRolePrefix+awsKeyRoles[0]),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.0", awsPolicyRolePrefix+awsKeyRoles[1]),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
				),
			},
		},
	})
}
