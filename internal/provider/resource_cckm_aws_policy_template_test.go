package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsPolicyTemplateDefaultPolicy(t *testing.T) {
	if _, ok := initCckmAwsTest(); !ok {
		t.Skip()
	}
	createPolicyTemplateConfig := `
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
			regions       = data.ciphertrust_aws_account_details.account_details.regions
		}
		resource "ciphertrust_aws_policy_template" "policy_template" {
			kms  = ciphertrust_aws_kms.kms.id
			name = "%s"
		}`
	resourceName := "ciphertrust_aws_policy_template.policy_template"
	templateName := "PolicyTemplate-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(createPolicyTemplateConfig, templateName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "policy"),
					resource.TestCheckResourceAttr(resourceName, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "key_admins_roles.%", "0"),
				),
			},
		},
	})
}
