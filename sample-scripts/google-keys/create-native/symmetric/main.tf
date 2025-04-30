terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.10-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name  = "gcp-connection-${lower(random_id.random.hex)}"
  aes_max_key_name = "aes-max-params-${lower(random_id.random.hex)}"
  aes_min_key_name = "aes-min-params-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.name
  name           = var.keyring
  project_id     = var.gcp_project
}

# Minimum input parameters for a symmetric key
resource "ciphertrust_gcp_key" "gcp_aes_key_min_params" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.aes_min_key_name
}
output "gcp_aes_key_min_params" {
  value = ciphertrust_gcp_key.gcp_aes_key_min_params
}

# Maximum input parameters for a symmetric key
resource "ciphertrust_gcp_key" "gcp_aes_key_max_params" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  key_labels = {
    label_key3 = "label-value3"
    label_key2 = "label-value2"
  }
  name               = local.aes_max_key_name
  next_rotation_time = "2025-07-31T17:18:37Z"
  protection_level   = "SOFTWARE"
  purpose            = "ENCRYPT_DECRYPT"
  rotation_period    = "360005s"
}
output "gcp_ec_key_max_params" {
  value = ciphertrust_gcp_key.gcp_aes_key_max_params
}
