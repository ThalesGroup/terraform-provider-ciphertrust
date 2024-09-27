terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.6-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  key_name        = "cm-ec-upload-${lower(random_id.random.hex)}"
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
  curve     = "secp256k1"
}
output "ec_cm_key_id" {
  value = ciphertrust_cm_key.cm_key.id
}

# Upload the AES CipherTrust key Google Cloud
resource "ciphertrust_gcp_key" "gcp_ec_key" {
  algorithm        = "EC_SIGN_SECP256K1_SHA256"
  key_ring         = ciphertrust_gcp_keyring.keyring.id
  name             = local.key_name
  protection_level = "HSM"
  upload_key {
    source_key_identifier = ciphertrust_cm_key.cm_key.id
  }
}
output "gcp_ec_key" {
  value = ciphertrust_gcp_key.gcp_ec_key
}
