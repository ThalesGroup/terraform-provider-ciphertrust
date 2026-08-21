terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {

}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-oci-acls-${lower(random_id.random.hex)}"
  user_name       = "tf-oci-acls-user-${lower(random_id.random.hex)}"
  group_name      = "tf-oci-acls-group-${lower(random_id.random.hex)}"
  user_password   = "Secure-${upper(random_id.random.hex)}-1!"
}

resource "ciphertrust_oci_connection" "connection" {
  name                = local.connection_name
  key_file            = var.oci_key_file
  pub_key_fingerprint = var.oci_pub_key_fingerprint
  region              = var.oci_region
  tenancy_ocid        = var.oci_tenancy_ocid
  user_ocid           = var.oci_user_ocid
}

# Use the ciphertrust_get_oci_regions datasource to get a list of regions
data "ciphertrust_get_oci_regions" "regions" {
  connection_id = ciphertrust_oci_connection.connection.id
}

# Use the ciphertrust_get_oci_compartments datasource to get a list of compartments
data "ciphertrust_get_oci_compartments" "compartments" {
  connection_id = ciphertrust_oci_connection.connection.id
}

# Use the ciphertrust_get_oci_vaults datasource to get a list of available vaults
data "ciphertrust_get_oci_vaults" "vaults" {
  connection_id  = ciphertrust_oci_connection.connection.id
  compartment_id = data.ciphertrust_get_oci_compartments.compartments.compartments.0.id
  region         = data.ciphertrust_get_oci_regions.regions.oci_regions.0
}

# Create an OCI vault using information obtained from the datasources
resource "ciphertrust_oci_vault" "vault" {
  region        = data.ciphertrust_get_oci_regions.regions.oci_regions.0
  connection_id = ciphertrust_oci_connection.connection.id
  vault_id      = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
}

# Create a CipherTrust Manager user
resource "ciphertrust_user" "user" {
  username = local.user_name
  password = local.user_password
}

# Create an ACL that will be added to the vault for the user
resource "ciphertrust_oci_acl" "user_acl" {
  vault_id = ciphertrust_oci_vault.vault.id
  user_id  = ciphertrust_user.user.user_id
  actions  = ["view", "keycreate"]
}

# Create a CipherTrust Manager group
resource "ciphertrust_groups" "group" {
  name = local.group_name
}

# Create an ACL that will be added to the vault for the group
resource "ciphertrust_oci_acl" "group_acl" {
  vault_id = ciphertrust_oci_vault.vault.id
  group    = ciphertrust_groups.group.name
  actions  = ["view", "keyupdate"]
}

# List vaults after creating the acl resources
data "ciphertrust_oci_vault_list" "vaults" {
  depends_on = [ciphertrust_oci_acl.user_acl, ciphertrust_oci_acl.group_acl]
}
output "vaults" {
  value = data.ciphertrust_oci_vault_list.vaults
}
