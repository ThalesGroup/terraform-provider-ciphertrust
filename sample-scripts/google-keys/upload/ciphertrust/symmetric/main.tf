terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  key_name        = "cm-aes-upload-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.connection.id
  name           = var.keyring
  project_id     = var.gcp_project
}

# Create an AES CipherTrust key
resource "ciphertrust_cm_key" "aes_cm_key" {
  name      = local.key_name
  algorithm = "AES"
}
output "aes_cm_key" {
  value = ciphertrust_cm_key.aes_cm_key
}

# Upload the AES CipherTrust key to Google Cloud
resource "ciphertrust_gcp_key" "gcp_aes_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.key_name
  upload_key {
    source_key_identifier = ciphertrust_cm_key.aes_cm_key.id
  }
}
output "gcp_aes_key" {
  value = ciphertrust_gcp_key.gcp_aes_key
}
