# Pre-requisites for OCI BYOK key versions - OCI connection, OCI Vault, OCI BYOK Key

# Define an OCI connection
resource "ciphertrust_oci_connection" "connection" {
  key_file            = "path-to-or-contents-of-oci-key-file"
  name                = "name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Define an OCI Vault
resource "ciphertrust_oci_vault" "vault" {
  connection_id = ciphertrust_oci_connection.connection.id
  vault_id      = "vault-ocid"
  region        = "region"
}

# Define a CipherTrust Manager source key
resource "ciphertrust_cm_key" "source_key" {
  name       = "name"
  algorithm  = "AES"
  usage_mask = 60
}

# Define an OCI BYOK key
resource "ciphertrust_oci_byok_key" "key" {
  # Required parameters
  name          = "name"
  source_key_id = ciphertrust_cm_key.source_key.id
  vault         = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    compartment_id  = "compartment-ocid"
    protection_mode = "SOFTWARE"
  }
}

# Define a CipherTrust Manager source key for the key version
resource "ciphertrust_cm_key" "version_source_key" {
  name       = "name"
  algorithm  = "AES"
  usage_mask = 60
}

# Add a BYOK key version
resource "ciphertrust_oci_byok_key_version" "version" {
  # Required parameters
  cckm_key_id   = ciphertrust_oci_byok_key.key.id
  source_key_id = ciphertrust_cm_key.version_source_key.id
  # Optional parameters
  source_key_tier            = "local"
  schedule_for_deletion_days = 14
}
