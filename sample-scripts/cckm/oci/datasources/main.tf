terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-oci-ds-${lower(random_id.random.hex)}"
}

# Define an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = var.oci_key_file
  name                = local.connection_name
  pub_key_fingerprint = var.oci_pub_key_fingerprint
  region              = var.oci_region
  tenancy_ocid        = var.oci_tenancy_ocid
  user_ocid           = var.oci_user_ocid
}

# Define an OCI vault
resource "ciphertrust_oci_vault" "vault" {
  connection_id = ciphertrust_oci_connection.oci_connection.id
  vault_id      = var.oci_vault_ocid
  region        = var.oci_region
}

# List the OCI connection by name
data "ciphertrust_oci_connection_list" "by_name" {
  filters = {
    name = ciphertrust_oci_connection.oci_connection.name
  }
}
output "connection_by_name" {
  value = data.ciphertrust_oci_connection_list.by_name
}

# List the OCI compartments saved in CipherTrust Manager.
# Compartments are saved when a vault in the compartment is added to CipherTrust Manager.
data "ciphertrust_oci_compartments_list" "compartments" {
  filters = {
    compartment_id = ciphertrust_oci_vault.vault.compartment_id
  }
}
output "compartments" {
  value = data.ciphertrust_oci_compartments_list.compartments
}

# List the Object Storage buckets in the vault's compartment.
# A bucket can be used by a vault for key backups with bucket_name and bucket_namespace.
data "ciphertrust_get_oci_buckets" "buckets" {
  connection_id  = ciphertrust_oci_connection.oci_connection.id
  compartment_id = ciphertrust_oci_vault.vault.compartment_id
}
output "buckets" {
  value = data.ciphertrust_get_oci_buckets.buckets
}
