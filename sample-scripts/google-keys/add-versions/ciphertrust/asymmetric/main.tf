terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta6"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  key_name        = "cm-ec-version-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.id
  name           = var.keyring
  project_id     = var.gcp_project
}

# Create an AES CipherTrust key
resource "ciphertrust_cm_key" "cm_key" {
  name      = local.key_name
  algorithm = "EC"
  curve     = "secp384r1"
}
output "cm_key" {
  value = ciphertrust_cm_key.cm_key
}

# Create a Gooogle Cloud EC key and add a new version
resource "ciphertrust_gcp_key" "gcp_aes_key" {
  # Versions can be added on create or update
  add_version {
    is_native       = false
    algorithm       = "EC_SIGN_P384_SHA384"
    source_key_id   = ciphertrust_cm_key.cm_key.id
    source_key_tier = "local"
  }
  algorithm = "EC_SIGN_P256_SHA256"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.key_name
}
output "gcp_aes_key" {
  value = ciphertrust_gcp_key.gcp_aes_key
}
