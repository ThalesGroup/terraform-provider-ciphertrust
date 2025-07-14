package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const defaultPolicy = `{
    "Version": "2012-10-17",
    "Id": "kms-tf-1",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions 1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "kms:*",
            "Resource": "*"
        }
    ]
}`

func TestCckmAwsPolicyTemplate(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	keyUsers := getAwsUsers()
	if len(keyUsers) != 2 {
		t.Skip("AWS_KEY_USERS is not exported or doesn't contain 2 roles")
	}
	keyRoles := getAwsRoles()
	if len(keyRoles) != 2 {
		t.Skip("AWS_KEY_ROLES is not exported or doesn't contain 2 users")
	}
	users := fmt.Sprintf("\"%s\",\"%s\"", keyUsers[0], keyUsers[1])
	roles := fmt.Sprintf("\"%s\",\"%s\"", keyRoles[0], keyRoles[1])
	createConfigEx1 := `
		resource "ciphertrust_aws_policy_template" "policy_template_ex1" {
			kms    = ciphertrust_aws_kms.kms.id
			name   = "%s"   
			policy = jsonencode(
				{
					"Version": "2012-10-17",
					"Id": "kms-tf-1",
					"Statement": [
						{
							"Sid": "Enable IAM User Permissions 1",
							"Effect": "Allow",
							"Principal": {
								"AWS": "*"
							},
							"Action": "kms:*",
							"Resource": "*"
						}
					]
				}
			)
		}`
	updateConfigEx1 := `
		resource "ciphertrust_aws_policy_template" "policy_template_ex1" {
			kms         = ciphertrust_aws_kms.kms.id
			name        = "%s"
			key_admins  = [%s]
			key_users   = [%s]
			key_admins_roles  = [%s]
			key_users_roles   = [%s]
			auto_push = true
		}`
	resourceNameEx1 := "ciphertrust_aws_policy_template.policy_template_ex1"
	templateNameEx1 := "tf-template-" + uuid.New().String()[:8]
	createConfigStrEx1 := fmt.Sprintf(createConfigEx1, templateNameEx1)
	updateConfigStrEx1 := fmt.Sprintf(updateConfigEx1, templateNameEx1, users, users, roles, roles)

	createConfigEx2 := `
		variable "policy" {
			type    = string
			default = <<-EOT
					{"Version":"2012-10-17","Id":"kms-tf-1","Statement":[{"Sid":"Enable IAM User Permissions 1","Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*"}]}
			EOT
		}
		resource "ciphertrust_aws_policy_template" "policy_template_ex2" {
			kms    = ciphertrust_aws_kms.kms.id
			name   = "%s"
			policy = var.policy
		}`
	resourceNameEx2 := "ciphertrust_aws_policy_template.policy_template_ex2"
	templateNameEx2 := "tf-template-" + uuid.New().String()[:8]
	createConfigStrEx2 := fmt.Sprintf(createConfigEx2, templateNameEx2)

	createConfigEx3 := `
		resource "ciphertrust_aws_policy_template" "policy_template_ex3" {
			kms    = ciphertrust_aws_kms.kms.id
			name   = "%s"
			policy = <<-EOT
				%s
			EOT
		}`
	resourceNameEx3 := "ciphertrust_aws_policy_template.policy_template_ex3"
	templateNameEx3 := "tf-template-" + uuid.New().String()[:8]
	createConfigStrEx3 := fmt.Sprintf(createConfigEx3, templateNameEx3, defaultPolicy)

	createConfigEx4 := `
		resource "ciphertrust_aws_policy_template" "policy_template_without_policy" {
			kms         = ciphertrust_aws_kms.kms.id
			name        = "%s"
			key_admins  = [%s]
			key_users   = [%s]
			key_admins_roles  = [%s]
			key_users_roles   = [%s]
		}`
	updateConfigEx4 := `
		resource "ciphertrust_aws_policy_template" "policy_template_without_policy" {
			kms    = ciphertrust_aws_kms.kms.id
			name   = "%s"   
			policy = jsonencode(
				{
					"Version": "2012-10-17",
					"Id": "kms-tf-1",
					"Statement": [
						{
							"Sid": "Enable IAM User Permissions 1",
							"Effect": "Allow",
							"Principal": {
								"AWS": "*"
							},
							"Action": "kms:*",
							"Resource": "*"
						}
					]
				}
			)
		}`
	resourceNameEx4 := "ciphertrust_aws_policy_template.policy_template_without_policy"
	templateNameEx4 := "tf-template-" + uuid.New().String()[:8]
	createConfigStrEx4 := fmt.Sprintf(createConfigEx4, templateNameEx4, users, users, roles, roles)
	updateConfigStrEx4 := fmt.Sprintf(updateConfigEx4, templateNameEx4)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + createConfigStrEx1 + createConfigStrEx2 + createConfigStrEx3 + createConfigStrEx4,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceNameEx1, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx1, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_admins_roles.%", "0"),

					resource.TestCheckResourceAttrSet(resourceNameEx2, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx2, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_admins_roles.%", "0"),

					resource.TestCheckResourceAttrSet(resourceNameEx3, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx3, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_admins_roles.%", "0"),

					resource.TestCheckResourceAttrSet(resourceNameEx4, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx4, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_users.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_users_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_admins.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_admins_roles.#", "2"),
					testCheckAttributeContains(resourceNameEx4, "policy", append(keyUsers, keyRoles...), true),
				),
			},
			{
				Config: awsConnectionResource + updateConfigStrEx1 + updateConfigStrEx4,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceNameEx1, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx1, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_users.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_users_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_admins.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_admins_roles.#", "2"),
					testCheckAttributeContains(resourceNameEx1, "policy", append(keyUsers, keyRoles...), true),

					resource.TestCheckResourceAttrSet(resourceNameEx4, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx4, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_admins_roles.%", "0"),

					testVerifyResourceDeleted(resourceNameEx2),
					testVerifyResourceDeleted(resourceNameEx3),
				),
			},
			{
				Config: awsConnectionResource + createConfigStrEx1 + createConfigStrEx2 + createConfigStrEx3 + createConfigStrEx4,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceNameEx1, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx1, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx1, "key_admins_roles.%", "0"),

					resource.TestCheckResourceAttrSet(resourceNameEx2, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx2, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx2, "key_admins_roles.%", "0"),

					resource.TestCheckResourceAttrSet(resourceNameEx3, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx3, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_users.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_users_roles.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_admins.%", "0"),
					resource.TestCheckResourceAttr(resourceNameEx3, "key_admins_roles.%", "0"),

					resource.TestCheckResourceAttrSet(resourceNameEx4, "id"),
					resource.TestCheckResourceAttrSet(resourceNameEx4, "policy"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_users.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_users_roles.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_admins.#", "2"),
					resource.TestCheckResourceAttr(resourceNameEx4, "key_admins_roles.#", "2"),
					testCheckAttributeContains(resourceNameEx4, "policy", append(keyUsers, keyRoles...), true),
				),
			},
			{
				ResourceName:      resourceNameEx1,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"policy",
				},
			},
			{
				ResourceName:      resourceNameEx2,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"policy",
				},
			},
			{
				ResourceName:      resourceNameEx3,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"policy",
				},
			},
			{
				ResourceName:      resourceNameEx4,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"policy",
				},
			},
		},
	})
}
