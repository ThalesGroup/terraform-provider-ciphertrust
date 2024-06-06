# Create an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = "oci-key-file"
  name                = "connection-name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}

# Create an OCI issuer resource
resource "ciphertrust_oci_issuer" "issuer" {
  name              = "issuer-name"
  openid_config_url = "open-config-url"
}

# Create an OCI external vault that will only accept CipherTrust keys
resource "ciphertrust_oci_external_vault" "vault_with_connection" {
  client_application_id = "oci-client-application-id"
  connection_id         = ciphertrust_oci_connection.oci_connection.id
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  source_key_tier       = "local"
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
  cckm_vault_id = ciphertrust_oci_external_vault.vault_with_connection.id
  name          = "key-name"
  source_key_id = ciphertrust_cm_key.ciphertrust_key.id
}

# Create a tenancy resource
resource "ciphertrust_oci_tenancy" "tenancy" {
  tenancy_ocid = "tenancy-ocid"
  tenancy_name = "tenancy-name"
}

# Create an OCI external vault using a tenancy resource that will only accept Hsm-Luna keys
resource "ciphertrust_oci_external_vault" "vault_with_tenancy" {
  client_application_id = "oci-client-application-id"
  issuer_id             = ciphertrust_oci_issuer.issuer.id
  source_key_tier       = "hsm-luna"
  tenancy_id            = ciphertrust_oci_tenancy.tenancy.id
  vault_name            = "vault-name"
}

# Create a ciphertrust_hsm_server resource
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = "hsm-ip"
  hsm_certificate = "hsm-server.pem"
}

# Create a ciphertrust_hsm_connection resource
resource "ciphertrust_hsm_connection" "hsm_connection" {
  is_ha_enabled = true
  hostname    = "hsm-ip"
  server_id   = ciphertrust_hsm_server.hsm_server.id
  name        = "connection-name"
  partitions {
    partition_label = "partition-label"
    serial_number   = "serial-number"
  }
  partition_password = "partition-password"
}

# Create a ciphertrust_hsm_partition resource
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}

# Create a Hsm-Luna AES key that is can be added the external vault
resource "ciphertrust_hsm_key" "hsm_luna_key" {
  hyok_key     = true
  key_size     = 256
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
}

# Add the key to the vault
resource "ciphertrust_oci_external_key" "external_key" {
  cckm_vault_id   = ciphertrust_oci_external_vault.vault_with_tenancy.id
  name            = "key-name"
  source_key_id   = ciphertrust_hsm_key.hsm_luna_key.id
  source_key_tier = "hsm-luna"
}
