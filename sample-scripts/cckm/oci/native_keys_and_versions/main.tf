terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  oci_key_file        = var.oci_key_file
  pubkey_fingerprint  = var.oci_pub_key_fingerprint
  region              = var.oci_region
  tenancy_ocid        = var.oci_tenancy_ocid
  user_ocid           = var.oci_user_ocid
  vault_ocid          = var.oci_vault_ocid
  connection_name     = "tf-${lower(random_id.random.hex)}"
  cm_key_name         = "tf-${lower(random_id.random.hex)}"
  oci_key_name        = "tf-${lower(random_id.random.hex)}"
  cm_key_version_name = "tf-ver-${lower(random_id.random.hex)}"
}

# Define an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = local.oci_key_file
  name                = local.connection_name
  pub_key_fingerprint = local.pubkey_fingerprint
  region              = local.region
  tenancy_ocid        = local.tenancy_ocid
  user_ocid           = local.user_ocid
}

# Get compartments for this connection
data "ciphertrust_get_oci_compartments" "compartments" {
  connection_id = ciphertrust_oci_connection.oci_connection.id
}

# Define an OCI vault
resource "ciphertrust_oci_vault" "vault" {
  connection_id = ciphertrust_oci_connection.oci_connection.id
  vault_id      = local.vault_ocid
  region        = local.region
}

# Define an RSA CipherTrust key
resource "ciphertrust_cm_key" "cm_rsa_key" {
  name       = local.cm_key_name
  algorithm  = "RSA"
  usage_mask = 60
  key_size   = 2048
}

# Define an OCI native key
resource "ciphertrust_oci_key" "native_key" {
  name  = local.oci_key_name
  vault = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    algorithm       = "AES"
    compartment_id  = tolist(data.ciphertrust_get_oci_compartments.compartments.compartments)[0].id
    length          = 32
    protection_mode = "SOFTWARE"
  }
}

# Define an AES CipherTrust key for the key version
resource "ciphertrust_cm_key" "cm_rsa_version" {
  name       = local.cm_key_version_name
  algorithm  = "AES"
  usage_mask = 60
  key_size   = 256
}

# Add a byok key version to the key
resource "ciphertrust_oci_byok_key_version" "byok_version" {
  cckm_key_id   = ciphertrust_oci_key.native_key.id
  source_key_id = ciphertrust_cm_key.cm_rsa_version.id
}

# Add a native version to the key
resource "ciphertrust_oci_key_version" "native_version" {
  cckm_key_id = ciphertrust_oci_key.native_key.id
}

# List all OCI key versions of the key
data "ciphertrust_oci_key_version_list" "ds_versions" {
  key_id     = ciphertrust_oci_key.native_key.id
  depends_on = [ciphertrust_oci_key_version.native_version, ciphertrust_oci_byok_key_version.byok_version]
}
output "version_list" {
  value = data.ciphertrust_oci_key_version_list.ds_versions
}

# List the key
data "ciphertrust_oci_key_list" "ds_key" {
  filters = {
    id = ciphertrust_oci_key.native_key.id
  }
  depends_on = [ciphertrust_oci_key_version.native_version, ciphertrust_oci_byok_key_version.byok_version]
}
output "key_list" {
  value = data.ciphertrust_oci_key_list.ds_key
}
