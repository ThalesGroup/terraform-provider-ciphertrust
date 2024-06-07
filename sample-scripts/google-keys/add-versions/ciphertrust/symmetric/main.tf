terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.5-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  key_name        = "cm-aes-version-${lower(random_id.random.hex)}"
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
  algorithm = "AES"
}

# Create a Google Cloud symmetric key and add a new version
resource "ciphertrust_gcp_key" "gcp_aes_key" {
  add_version {
    is_native       = false
    algorithm       = "GOOGLE_SYMMETRIC_ENCRYPTION"
    source_key_id   = ciphertrust_cm_key.cm_key.id
    source_key_tier = "local"
  }
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.key_name
}
output "gcp_aes_key" {
  value = ciphertrust_gcp_key.gcp_aes_key
}
