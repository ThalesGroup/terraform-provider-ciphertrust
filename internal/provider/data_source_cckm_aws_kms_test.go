package provider

import (
	"fmt"
	"github.com/google/uuid"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsDataSourceKms(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	kmsTwoConfig := `
		resource "ciphertrust_aws_kms" "kms_two" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection  = ciphertrust_aws_connection.aws_connection.id
			name           = "%s"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[3],
				data.ciphertrust_aws_account_details.account_details.regions[4],
			]
		}`
	kmsTwoConfigStr := fmt.Sprintf(kmsTwoConfig, "tf-"+uuid.New().String()[:8])

	acls := `
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "admin"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_aws_acl" "user1_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = ["keycreate"]
		}
		resource "ciphertrust_aws_acl" "group1_acl" {
		kms_id  = ciphertrust_aws_kms.kms.id
		group   = ciphertrust_groups.group.id
		actions = ["keyupdate", "keydelete"]
		}
		resource "ciphertrust_aws_acl" "user2_acl" {
		kms_id  = ciphertrust_aws_kms.kms_two.id
		user_id = ciphertrust_user.user.id
		actions = ["keycreate"]
		}
		resource "ciphertrust_aws_acl" "group2_acl" {
		kms_id  = ciphertrust_aws_kms.kms_two.id
		group   = ciphertrust_groups.group.id
		actions = ["keyupdate", "keydelete"]
	}`
	aclsConfigStr := fmt.Sprintf(acls, "tf-"+uuid.New().String()[:8], "tf-"+uuid.New().String()[:8])

	noFilters := `
		data "ciphertrust_aws_kms_list" "all_kms" {
			depends_on = [ciphertrust_aws_kms.kms, ciphertrust_aws_kms.kms_two]
		}`
	byName := `
		data "ciphertrust_aws_kms_list" "by_name" {
			filters = {
				name = ciphertrust_aws_kms.kms_two.name 
			}
		}`
	byID := `
		data "ciphertrust_aws_kms_list" "by_id" {
			filters = {
				id = ciphertrust_aws_kms.kms.id
			}
		}`
	noFiltersWithAcls := `
		data "ciphertrust_aws_kms_list" "all_kms" {
			depends_on = [ciphertrust_aws_kms.kms, ciphertrust_aws_kms.kms_two,
						ciphertrust_aws_acl.user1_acl, ciphertrust_aws_acl.user2_acl, 
						ciphertrust_aws_acl.group1_acl, ciphertrust_aws_acl.group2_acl]
		}`

	dsAllKmsResources := "data.ciphertrust_aws_kms_list.all_kms"
	dsByName := "data.ciphertrust_aws_kms_list.by_name"
	dsByID := "data.ciphertrust_aws_kms_list.by_id"
	kmsOneResourceName := "ciphertrust_aws_kms.kms"
	kmsTwoResourceName := "ciphertrust_aws_kms.kms_two"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + kmsTwoConfigStr + noFilters,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsAllKmsResources, "kms.#", "2"),
				),
			},
			{
				Config: awsConnectionResource + kmsTwoConfigStr + byName,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsByName, "kms.#", "1"),
					resource.TestCheckResourceAttrPair(dsByName, "kms.0.regions.#", kmsTwoResourceName, "regions.#"),
					resource.TestCheckResourceAttrPair(kmsTwoResourceName, "id", dsByName, "kms.0.id"),
				),
			},
			{
				Config: awsConnectionResource + kmsTwoConfigStr + byID,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsByID, "kms.#", "1"),
					resource.TestCheckResourceAttrPair(dsByID, "kms.0.regions.#", kmsOneResourceName, "regions.#"),
					resource.TestCheckResourceAttrPair(kmsOneResourceName, "id", dsByID, "kms.0.id"),
				),
			},
			{
				Config: awsConnectionResource + kmsTwoConfigStr + aclsConfigStr + noFiltersWithAcls,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsAllKmsResources, "kms.0.acls.#", "2"),
					resource.TestCheckResourceAttr(dsAllKmsResources, "kms.1.acls.#", "2"),
				),
			},
		},
	})
}
