# Create a tenancy resource
resource "ciphertrust_oci_tenancy" "oci_tenancy" {
  tenancy_ocid = "tenancy-ocid"
  tenancy_name = "tenancy-name"
}

# Create an OCI issuer resource
resource "ciphertrust_oci_issuer" "oci_issuer" {
  name              = "issuer-name"
  openid_config_url = "open-config-url"
}

# Create an OCI external vault that will accept both CipherTrust and Hsm-Luna keys
resource "ciphertrust_oci_external_vault" "external_vault" {
  client_application_id = "oci-client-application-id"
  issuer_id             = ciphertrust_oci_issuer.oci_issuer.id
  tenancy_id            = ciphertrust_oci_tenancy.oci_tenancy.id
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

# Create another CipherTrust key that can be added to the vault
resource "ciphertrust_cm_key" "key_version" {
  name         = "key-name"
  algorithm    = "AES"
  undeletable  = true
  unexportable = true
}

# Add it as a version of the key
resource "ciphertrust_oci_external_key_version" "key_version" {
  key_id          = ciphertrust_oci_external_key.external_key.id
  source_key_id   = ciphertrust_cm_key.key_version.id
  source_key_tier = "local"
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

# Create a hsm-luna key that is able to be utilized by the external vault
resource "ciphertrust_hsm_key" "hsm_luna_key" {
  hyok_key     = true
  key_size     = 256
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
}

# Add the hsm-luna key to the vault
resource "ciphertrust_oci_external_key" "hsm_luna_external_key" {
  cckm_vault_id   = ciphertrust_oci_external_vault.external_vault.id
  name            = "key-name"
  source_key_id   = ciphertrust_hsm_key.hsm_luna_key.id
  source_key_tier = "hsm-luna"
}

# Create another hsm-luna key
resource "ciphertrust_hsm_key" "hsm_luna_key_version" {
  hyok_key     = true
  key_size     = 256
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
}

# Add it as a version of the key
resource "ciphertrust_oci_external_key_version" "key_version_luna" {
  key_id          = ciphertrust_oci_external_key.hsm_luna_external_key.id
  source_key_id   = ciphertrust_hsm_key.hsm_luna_key_version.id
  source_key_tier = "hsm-luna"
}
