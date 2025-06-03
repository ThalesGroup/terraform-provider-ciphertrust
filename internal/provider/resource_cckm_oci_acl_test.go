package provider

import (
	"fmt"
	"github.com/google/uuid"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmOciAcl(t *testing.T) {

	ociKeyFile := os.Getenv("OCI_KEYFILE")
	ociPubKeyFP := os.Getenv("OCI_PUBKEY_FP")
	ociRegion := os.Getenv("OCI_REGION")
	ociTenancyOCID := os.Getenv("OCI_TENANCY_OCID")
	ociUserOCID := os.Getenv("OCI_USER_OCID")
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
			limit = 1
		}
		data "ciphertrust_get_oci_vaults" "vaults" {
			limit = 1
			connection_id = ciphertrust_oci_connection.connection.name
			compartment_id = data.ciphertrust_get_oci_compartments.compartments.compartments.0.id
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		 resource "ciphertrust_oci_vault" "vault" {
		   region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		   connection_id = ciphertrust_oci_connection.connection.name
		   vault_id = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
		}`

	createACLsConfig := `
		%s
		resource "ciphertrust_cm_user" "user" {
			username = "%s"
			password = "admin"
		}
		resource "ciphertrust_cm_group" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_cm_user.user.id
			actions  = ["view", "keycreate"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_cm_group.group.id
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
		resource "ciphertrust_cm_user" "user" {
			username = "%s"
			password = "admin"
		}
		resource "ciphertrust_cm_group" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_cm_user.user.id
			actions  = ["view", "keycreate", "keydelete"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_cm_group.group.id
			actions  = ["view", "keycreate", "keyupdate", "keydelete"]
		}`

	removeAclActionsConfig := `
		%s
		resource "ciphertrust_cm_user" "user" {
			username = "%s"
			password = "admin"
		}
		resource "ciphertrust_cm_group" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_cm_user.user.id
			actions  = ["view"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_cm_group.group.id
			actions  = ["view", "keycreate", "keydelete"]
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
	createAclsActionsConfigStr := fmt.Sprintf(createACLsConfig, createVaultConfigStr, userName, groupName)
	addAclActionsConfigStr := fmt.Sprintf(addAclActionsConfig, createVaultConfigStr, userName, groupName)
	removeAclActionsConfigStr := fmt.Sprintf(removeAclActionsConfig, createVaultConfigStr, userName, groupName)
	deleteAclsConfigStr := createVaultConfigStr
	applyConfigStr := createVaultConfigStr + dataSourceConfig
	userACLResourceName := "ciphertrust_oci_acl.user_acl"
	groupACLResourceName := "ciphertrust_oci_acl.group_acl"
	vaultResourceName := "ciphertrust_oci_vault.vault"
	vaultDatasourceName := "data.ciphertrust_oci_vault_list.vault_ds"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "2"),
					resource.TestCheckResourceAttr(groupACLResourceName, "actions.#", "3"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "2"),
				),
			},
			{
				Config: addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "3"),
					resource.TestCheckResourceAttr(groupACLResourceName, "actions.#", "4"),
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "2"),
				),
			},
			{
				Config: removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "1"),
					resource.TestCheckResourceAttr(groupACLResourceName, "actions.#", "3"),
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
