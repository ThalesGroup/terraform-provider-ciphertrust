terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.1-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "google-connection-${lower(random_id.random.hex)}"
  key_name        = "google-key-data-source-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}
output "gcp_connection_id" {
  value = ciphertrust_gcp_connection.connection.id
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.connection.name
  name           = var.keyring
  project_id     = var.gcp_project
}

# Create a Google cloud Key
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
  key_ring         = ciphertrust_gcp_keyring.keyring.id
  name             = local.key_name
  protection_level = "SOFTWARE"
  purpose          = "ENCRYPT_DECRYPT"
}
output "gcp_key" {
  value = ciphertrust_gcp_key.gcp_key.id
}

# Get the key from the CipherTrust key ID
data "ciphertrust_gcp_key" "key_from_ciphertrust_id" {
  key_id = ciphertrust_gcp_key.gcp_key.key_id
}
output "key_from_ciphertrust_id" {
  value = data.ciphertrust_gcp_key.key_from_ciphertrust_id
}

# Get the GCP key data using key name and other values uniquely identify the key
data "ciphertrust_gcp_key" "gcp_key_data_using_multiple_values" {
  name        = ciphertrust_gcp_key.gcp_key.name
  key_ring    = ciphertrust_gcp_keyring.keyring.id
  project_id  = var.gcp_project
  location_id = "global"
}
output "gcp_key_data_using_multiple_values" {
  value = data.ciphertrust_gcp_key.gcp_key_data_using_multiple_values
}
