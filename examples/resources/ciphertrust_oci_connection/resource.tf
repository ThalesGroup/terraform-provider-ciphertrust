# Create an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = "oci-key-file"
  name                = "connection-name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Create an OCI issuer
resource "ciphertrust_oci_issuer" "oci_issuer" {
  name              = "issuer-name"
  openid_config_url = "open-config-url"
}

# Create an OCI external vault and assign it to the connection
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = "oci-client-application-id"
  connection_id         = ciphertrust_oci_connection.oci_connection.id
  issuer_id             = ciphertrust_oci_issuer.oci_issuer.id
  vault_name            = "vault-name"
}

# Create a CipherTrust key that can be added to the vault
resource "ciphertrust_cm_key" "ciphertrust_key" {
  name         = "key-name"
  algorithm    = "AES"
  undeletable  = true
  unexportable = true
}

# Add the key to the vault
resource "ciphertrust_oci_external_key" "external_key" {
  cckm_vault_id = ciphertrust_oci_external_vault.external_vault.id
  name          = "key-name"
  source_key_id = ciphertrust_cm_key.ciphertrust_key.id
}
