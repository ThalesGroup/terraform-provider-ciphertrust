package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmOCIAcl(t *testing.T) {

	ociKeyFile := os.Getenv("CCKM_OCI_KEY_FILE")
	ociPubKeyFP := os.Getenv("CCKM_OCI_FINGERPRINT")
	ociRegion := os.Getenv("CCKM_OCI_REGION")
	ociTenancyOCID := os.Getenv("CCKM_OCI_CONN_TENANCY")
	ociUserOCID := os.Getenv("CCKM_OCI_USER")
	ok := ociKeyFile != "" && ociPubKeyFP != "" && ociRegion != "" && ociTenancyOCID != "" && ociUserOCID != ""
	if !ok {
		t.Skip("Failed to set OCI connection variables")
	}

	createVaultConfig := `
		resource "ciphertrust_oci_connection" "connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}
		data "ciphertrust_get_oci_regions" "regions" {
			connection_id = ciphertrust_oci_connection.connection.name
		}
		data "ciphertrust_get_oci_compartments" "compartments" {
			connection_id = ciphertrust_oci_connection.connection.id
		}
		data "ciphertrust_get_oci_vaults" "vaults" {
			connection_id = ciphertrust_oci_connection.connection.id
			compartment_id = tolist(data.ciphertrust_get_oci_compartments.compartments.compartments)[0].id
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		 resource "ciphertrust_oci_vault" "vault" {
		   region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		   connection_id = ciphertrust_oci_connection.connection.id
		   vault_id = tolist(data.ciphertrust_get_oci_vaults.vaults.vaults)[0].vault_id
		}`

	createACLsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = ["view", "keycreate"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_groups.group.id
			actions  = ["view", "keyupdate", "keydelete"]
		}
		data "ciphertrust_oci_vault_list" "vault_ds" {
			depends_on = [ciphertrust_oci_acl.user_acl, ciphertrust_oci_acl.group_acl]
			filters = {
				name = ciphertrust_oci_vault.vault.name
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
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = ["view", "keycreate", "keydelete"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_groups.group.id
			actions  = ["view", "keycreate", "keyupdate", "keydelete"]
		}
		data "ciphertrust_oci_vault_list" "vault_ds" {
			depends_on = [ciphertrust_oci_acl.user_acl, ciphertrust_oci_acl.group_acl]
			filters = {
				name = ciphertrust_oci_vault.vault.name
			}
		}`

	// removeAclActionsConfig drops group_acl so Terraform destroys it, proving that
	// deleting the resource removes the group from the vault ACL. user_acl actions
	// are reduced to view-only. The data source confirms exactly 1 ACL remains.
	removeAclActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = ["view"]
		}
		data "ciphertrust_oci_vault_list" "vault_ds" {
			depends_on = [ciphertrust_oci_acl.user_acl]
			filters = {
				name = ciphertrust_oci_vault.vault.name
			}
		}`

	modifyPlanAclConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = %s
			user_id  = ciphertrust_user.user.id
			actions  = ["view"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_groups.group.id
			actions  = ["view", "keycreate", "keydelete"]
		}`

	// emptyActionsConfig is used only to verify that actions = [] is rejected at plan time.
	emptyActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = []
		}`

	dataSourceConfig := `
		data "ciphertrust_oci_vault_list" "vault_ds" {
			filters = {
				name = ciphertrust_oci_vault.vault.name
			}
		}`

	connectionName := "tf-" + uuid.New().String()[:8]
	createVaultConfigStr := fmt.Sprintf(createVaultConfig, ociKeyFile, connectionName,
		ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	userName := "tf-" + uuid.New().String()[:8]
	groupName := "tf-" + uuid.New().String()[:8]
	fakeVaultID := `"` + uuid.New().String() + `"`
	createAclsActionsConfigStr := fmt.Sprintf(createACLsConfig, createVaultConfigStr, userName, groupName)
	addAclActionsConfigStr := fmt.Sprintf(addAclActionsConfig, createVaultConfigStr, userName, groupName)
	removeAclActionsConfigStr := fmt.Sprintf(removeAclActionsConfig, createVaultConfigStr, userName, groupName)
	emptyActionsConfigStr := fmt.Sprintf(emptyActionsConfig, createVaultConfigStr, userName)
	modifyPlanConfigStr := fmt.Sprintf(modifyPlanAclConfig, createVaultConfigStr, userName, groupName, fakeVaultID)
	deleteAclsConfigStr := createVaultConfigStr
	applyConfigStr := createVaultConfigStr + dataSourceConfig
	userACLResourceName := "ciphertrust_oci_acl.user_acl"
	groupACLResourceName := "ciphertrust_oci_acl.group_acl"
	vaultResourceName := "ciphertrust_oci_vault.vault"
	vaultDatasourceName := "data.ciphertrust_oci_vault_list.vault_ds"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttrPair(userACLResourceName, "vault_id", vaultResourceName, "id"),
					resource.TestCheckResourceAttrPair(userACLResourceName, "user_id", "ciphertrust_user.user", "id"),
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "2"),
					resource.TestCheckResourceAttrSet(groupACLResourceName, "id"),
					resource.TestCheckResourceAttrPair(groupACLResourceName, "vault_id", vaultResourceName, "id"),
					resource.TestCheckResourceAttrPair(groupACLResourceName, "group", "ciphertrust_groups.group", "id"),
					resource.TestCheckResourceAttr(groupACLResourceName, "actions.#", "3"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "2"),
				),
			},
			{
				RefreshState: true,
			},
			{
				ResourceName:      userACLResourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      groupACLResourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "3"),
					resource.TestCheckResourceAttr(groupACLResourceName, "actions.#", "4"),
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "2"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "2"),
				),
			},
			{
				// group_acl is destroyed (group removed from vault ACL); user_acl actions
				// are reduced to view-only. The data source confirms exactly 1 ACL remains:
				// the user, not the group.
				Config: removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "1"),
					resource.TestCheckResourceAttrSet(vaultDatasourceName, "vaults.0.acls.0.user_id"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.0.group", ""),
				),
			},
			{
				// Verify that actions = [] is rejected at plan time by the schema validator.
				// An empty action set would remove the user from the vault ACL entirely;
				// deleting the resource is the correct way to remove all permissions.
				Config:      emptyActionsConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`at least 1`),
			},
			{
				// Verify ModifyPlan fires an error when vault_id is changed on an existing ACL.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				Config: deleteAclsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					testVerifyResourceDeleted(userACLResourceName),
					testVerifyResourceDeleted(groupACLResourceName),
				),
			},
			{
				Config: applyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "0"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "0"),
				),
			},
		},
	})
}
