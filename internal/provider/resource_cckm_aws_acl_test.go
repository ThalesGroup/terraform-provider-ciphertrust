package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSAcl(t *testing.T) {

	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	createACLsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
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
			password = "LongPassword1234++"
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
		}
		data "ciphertrust_aws_kms_list" "kms_ds" {
			depends_on = [ciphertrust_aws_acl.user_acl, ciphertrust_aws_acl.group_acl]
			filters = {
				name = ciphertrust_aws_kms.kms.name
			}
		}`

	removeAclActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = %s
			user_id = ciphertrust_user.user.id
			actions = ["view"]
		}
		data "ciphertrust_aws_kms_list" "kms_ds" {
			depends_on = [ciphertrust_aws_acl.user_acl]
			filters = {
				name = ciphertrust_aws_kms.kms.name
			}
		}`

	// emptyActionsConfig is used only to verify that actions = [] is rejected at plan time.
	emptyActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
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
	fakeKmsID := `"` + uuid.New().String() + `"`
	createAclsActionsConfigStr := fmt.Sprintf(createACLsConfig, awsConnectionResource, userName, groupName)
	addAclActionsConfigStr := fmt.Sprintf(addAclActionsConfig, awsConnectionResource, userName, groupName)
	removeAclActionsConfigStr := fmt.Sprintf(removeAclActionsConfig, awsConnectionResource, userName, groupName, "ciphertrust_aws_kms.kms.id")
	emptyActionsConfigStr := fmt.Sprintf(emptyActionsConfig, awsConnectionResource, userName)
	modifyPlanConfigStr := fmt.Sprintf(removeAclActionsConfig, awsConnectionResource, userName, groupName, fakeKmsID)
	deleteAclsConfigStr := awsConnectionResource
	datasourceConfigStr := awsConnectionResource + dataSourceConfig
	userACLResourceName := "ciphertrust_aws_acl.user_acl"
	groupACLResourceName := "ciphertrust_aws_acl.group_acl"
	kmsResourceName := "ciphertrust_aws_kms.kms"
	kmsDatasourceName := "data.ciphertrust_aws_kms_list.kms_ds"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
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
				RefreshState: true,
			},
			{
				// "actions" cannot be reconstructed from the API (the KMS returns the
				// expanded kms_actions set, not the raw user input), so it is ignored.
				ResourceName:            userACLResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"actions"},
			},
			{
				ResourceName:            groupACLResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"actions"},
			},
			{
				Config: addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "2"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
				),
			},
			{
				// group_acl is destroyed (group removed from KMS ACL); user_acl actions
				// are reduced to view-only. CCKM auto-expands "view" to viewnative plus
				// additional view permissions (viewhyokkey, viewkeystore, etc.).
				// The data source confirms exactly 1 ACL remains: the user, not the group.
				Config: removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "1"),
					resource.TestCheckResourceAttrSet(kmsDatasourceName, "kms.0.acls.0.user_id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.0.group", ""),
				),
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
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
				),
			},
			{
				// group_acl is destroyed (group removed from KMS ACL); user_acl actions
				// are reduced to view-only. CCKM auto-expands "view" to viewnative plus
				// additional view permissions (viewhyokkey, viewkeystore, etc.).
				// The data source confirms exactly 1 ACL remains: the user, not the group.
				Config: removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "1"),
					resource.TestCheckResourceAttrSet(kmsDatasourceName, "kms.0.acls.0.user_id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.0.group", ""),
				),
			},
			{
				// Verify that actions = [] is rejected at plan time by the schema validator.
				// An empty action set would remove the user from the KMS ACL entirely;
				// deleting the resource is the correct way to remove all permissions.
				Config:      emptyActionsConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`at least 1`),
			},
			{
				// Verify ModifyPlan fires an error when kms_id is changed on an existing ACL.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// user_acl is destroyed (all user actions revoked) and then the user
				// and group CM resources are deleted. CCKM cleans up residual ACL
				// entries asynchronously via a DB trigger after user/group deletion,
				// so the data source may still show acls.# = 1 immediately after the
				// apply finishes. The CM API confirms acls.# = 0 once the trigger fires.
				// We do not assert acls.# = 0 here due to this timing gap.
				Config: datasourceConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttrSet(kmsDatasourceName, "kms.0.id"),
				),
			},
		},
	})
}
