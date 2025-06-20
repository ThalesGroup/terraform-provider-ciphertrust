package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsAcl(t *testing.T) {

	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	createACLsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "admin"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = ["keycreate"]
		}
		resource "ciphertrust_aws_acl" "group_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			group   = ciphertrust_groups.group.id
			actions = ["keyupdate", "keydelete"]
		}
		data "ciphertrust_aws_kms_list" "kms_ds" {
			depends_on = [ciphertrust_aws_acl.user_acl, ciphertrust_aws_acl.group_acl]
			filters = {
				name = ciphertrust_aws_kms.kms.name
			}
		}`

	addAclActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "admin"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = ["keycreate", "keydelete"]
		}
		resource "ciphertrust_aws_acl" "group_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			group   = ciphertrust_groups.group.id
			actions = ["keycreate", "keyupdate", "keydelete"]
		}`

	removeAclActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "admin"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = []
		}`

	dataSourceConfig := `
		data "ciphertrust_aws_kms_list" "kms_ds" {
		filters = {
			name = ciphertrust_aws_kms.kms.name
		}
	}`

	userName := "tf-" + uuid.New().String()[:8]
	groupName := "tf-" + uuid.New().String()[:8]
	createAclsActionsConfigStr := fmt.Sprintf(createACLsConfig, awsConnectionResource, userName, groupName)
	addAclActionsConfigStr := fmt.Sprintf(addAclActionsConfig, awsConnectionResource, userName, groupName)
	removeAclActionsConfigStr := fmt.Sprintf(removeAclActionsConfig, awsConnectionResource, userName, groupName)
	deleteAclsConfigStr := awsConnectionResource
	datasourceConfigStr := awsConnectionResource + dataSourceConfig
	userACLResourceName := "ciphertrust_aws_acl.user_acl"
	groupACLResourceName := "ciphertrust_aws_acl.group_acl"
	kmsResourceName := "ciphertrust_aws_kms.kms"
	kmsDatasourceName := "data.ciphertrust_aws_kms_list.kms_ds"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
				),
			},
			{
				Config: addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "2"),
				),
			},
			{
				Config: removeAclActionsConfigStr,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: deleteAclsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					testVerifyResourceDeleted(userACLResourceName),
					testVerifyResourceDeleted(groupACLResourceName),
				),
			},
			{
				Config: createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
				),
			},
			{
				Config: addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "2"),
				),
			},
			{
				Config: removeAclActionsConfigStr,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: datasourceConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "0"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "0"),
				),
			},
		},
	})
}
