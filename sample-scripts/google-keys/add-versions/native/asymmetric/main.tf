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
  connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  key_name        = "gcp-ec-version-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = var.gcp_key_file
  name     = local.key_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.id
  name           = var.keyring
  project_id     = var.gcp_project
}

# Create an asymmetric key and add a new version
resource "ciphertrust_gcp_key" "gcp_ec_key" {
  add_version {
    is_native = true
  }
  algorithm = "EC_SIGN_P256_SHA256"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.key_name
}
output "gcp_ec_key" {
  value = ciphertrust_gcp_key.gcp_ec_key
}
