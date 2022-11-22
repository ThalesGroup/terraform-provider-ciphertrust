terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta7"
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

# Create a Google Key
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

# Get the key from the Terraform ID
data "ciphertrust_gcp_key" "key_from_terraform_id" {
  id = ciphertrust_gcp_key.gcp_key.id
}
output "key_from_terraform_id" {
  value = data.ciphertrust_gcp_key.key_from_terraform_id.id
}

# Get the key from the CipherTrust key ID
data "ciphertrust_gcp_key" "key_from_ciphertrust_id" {
  key_id = ciphertrust_gcp_key.gcp_key.key_id
}
output "key_from_ciphertrust_id" {
  value = data.ciphertrust_gcp_key.key_from_ciphertrust_id.id
}

# Get the key from key name and keyring name
data "ciphertrust_gcp_key" "key_from_key_name_and_keyring" {
  depends_on = [ciphertrust_gcp_key.gcp_key]
  name       = local.key_name
  key_ring   = var.keyring
}
output "key_from_key_name_and_keyring" {
  value = data.ciphertrust_gcp_key.key_from_key_name_and_keyring.id
}
