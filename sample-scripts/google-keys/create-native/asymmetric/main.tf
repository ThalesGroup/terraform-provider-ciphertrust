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
  connection_name  = "gcp-connection-${lower(random_id.random.hex)}"
  rsa_max_key_name = "rsa-max-params-${lower(random_id.random.hex)}"
  rsa_min_key_name = "rsa-min-params-${lower(random_id.random.hex)}"
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

# Minimum input parameters for an asymmetric key
resource "ciphertrust_gcp_key" "gcp_rsa_key_min_params" {
  algorithm = "RSA_DECRYPT_OAEP_2048_SHA256"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.rsa_min_key_name
}

output "gcp_rsa_key_min_params" {
  value = ciphertrust_gcp_key.gcp_rsa_key_min_params
}

# Maximum input parameters for an asymmetric key
resource "ciphertrust_gcp_key" "gcp_rsa_key_max_params" {
  algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  key_labels = {
    label_key1 = "label-value1"
    label_key2 = "label-value2"
  }
  name             = local.rsa_max_key_name
  protection_level = "SOFTWARE"
  purpose          = "ASYMMETRIC_SIGN"
}

output "gcp_rsa_key_max_params" {
  value = ciphertrust_gcp_key.gcp_rsa_key_max_params
}
