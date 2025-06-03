terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {

}

resource "ciphertrust_oci_connection" "connection" {
  name                = "example-connection-name"
  key_file            = "path-to-or-contents-of-the-private-key-file-"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Use the ciphertrust_get_oci_regions datasource to get a list of regions
data "ciphertrust_get_oci_regions" "regions" {
  connection_id = ciphertrust_oci_connection.connection.name
}

# Use the ciphertrust_get_oci_compartments datasource to get a list of compartments
data "ciphertrust_get_oci_compartments" "compartments" {
  connection_id = ciphertrust_oci_connection.connection.name
}

# Use the ciphertrust_get_oci_vaults datasource to get a list of available vaults
data "ciphertrust_get_oci_vaults" "vaults" {
  connection_id  = ciphertrust_oci_connection.connection.name
  compartment_id = data.ciphertrust_get_oci_compartments.compartments.compartments.0.id
  region         = data.ciphertrust_get_oci_regions.regions.oci_regions.0
}

# Create an OCI vault using information obtained from the datasources
resource "ciphertrust_oci_vault" "vault" {
  region        = data.ciphertrust_get_oci_regions.regions.oci_regions.0
  connection_id = ciphertrust_oci_connection.connection.name
  vault_id      = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
}

# Create a CipherTrust Manager user
resource "ciphertrust_cm_user" "user" {
  username = "example-user"
  password = "admin"
}

# Create an ACL that will be added to the vault for the user
resource "ciphertrust_oci_acl" "user_acl" {
  vault_id = ciphertrust_oci_vault.vault.id
  user_id  = ciphertrust_cm_user.user
  actions  = ["view", "keycreate"]
}

# Create a CipherTrust Manager group
resource "ciphertrust_cm_group" "group" {
  name = "example-group"
}

# Create an ACL that will be added to the vault for the group
resource "ciphertrust_oci_acl" "group_acl" {
  vault_id = ciphertrust_oci_vault.vault.id
  group    = ciphertrust_cm_group.group
  actions  = ["view", "keyupdate"]
}

# List vaults after creating the acl resources
data "ciphertrust_oci_vault_list" "vaults" {
  depends_on = [ciphertrust_oci_acl.user_acl,ciphertrust_oci_acl,group_acl ]
}
output "vaults" {
  value = data.ciphertrust_oci_vault_list.vaults
}
