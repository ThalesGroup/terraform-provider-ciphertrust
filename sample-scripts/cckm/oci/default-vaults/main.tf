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
  region         = data.ciphertrust_get_oci_regions.regions.regions.0
}

# Create an OCI vault using information obtained from above datasources
resource "ciphertrust_oci_vault" "vault" {
  region        = data.ciphertrust_get_oci_regions.regions.regions.0
  connection_id = ciphertrust_oci_connection.connection.name
  vault_id      = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
}

# List a CipherTrust Manager OCI vault by name
data "ciphertrust_oci_vault_list" "vault_by_name" {
  filters = {
    name = ciphertrust_oci_vault.vault.name
  }
}
output "vault_by_name" {
  value = data.ciphertrust_oci_vault_list.vault_by_name
}

# List a CipherTrust Manager OCI vault by resource ID
data "ciphertrust_oci_vault_list" "vault_by_id" {
  filters = {
    id = ciphertrust_oci_vault.vault.id
  }
}
output "vault_by_id" {
  value = data.ciphertrust_oci_vault_list.vault_by_id
}

# List all CipherTrust Manager OCI vaults
data "ciphertrust_oci_vault_list" "vault_no_filters" {
  depends_on = [ciphertrust_oci_vault.vault]
}
output "vault_no_filters" {
  value = data.ciphertrust_oci_vault_list.vault_no_filters
}
