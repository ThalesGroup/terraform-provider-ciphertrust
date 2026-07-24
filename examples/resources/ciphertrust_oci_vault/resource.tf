# Pre-requisites for an OCI Vault - OCI connection

# Define an OCI connection
resource "ciphertrust_oci_connection" "connection" {
  key_file            = "path-to-or-contents-of-oci-key-file"
  name                = "name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Define an OCI Vault.
resource "ciphertrust_oci_vault" "vault" {
  # Required parameters
  connection_id = ciphertrust_oci_connection.connection.id
  region        = "oci-region"
  vault_id      = "vault-ocid"
  # Optional parameters for Virtual Private Vaults
  bucket_name      = "bucket-name"
  bucket_namespace = "bucket-namespace"
}
