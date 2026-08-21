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
  connection_name = "tf-oci-vaults-${lower(random_id.random.hex)}"
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

# Create an OCI vault using information obtained from above datasources
resource "ciphertrust_oci_vault" "vault" {
  region        = data.ciphertrust_get_oci_regions.regions.oci_regions.0
  connection_id = ciphertrust_oci_connection.connection.id
  vault_id      = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
}

# List a CipherTrust Manager OCI vault by display name
data "ciphertrust_oci_vault_list" "vault_by_name" {
  filters = {
    display_name = ciphertrust_oci_vault.vault.name
  }
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
