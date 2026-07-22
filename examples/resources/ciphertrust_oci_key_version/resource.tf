# Pre-requisites for OCI native key versions - OCI connection, OCI Vault, OCI Key

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

# Define a native OCI key
resource "ciphertrust_oci_key" "key" {
  name  = "name"
  vault = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    algorithm       = "AES"
    compartment_id  = "compartment-ocid"
    length          = 32
    protection_mode = "SOFTWARE"
  }
}

# Add a native key version
resource "ciphertrust_oci_key_version" "version" {
  # Required parameters
  cckm_key_id = ciphertrust_oci_key.key.id
  # Optional parameters
  schedule_for_deletion_days = 14
}
