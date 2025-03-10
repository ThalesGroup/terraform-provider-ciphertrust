terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.8-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  gcp_connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  hsm_connection_name = "hsm-connection-${lower(random_id.random.hex)}"
  key_name            = "hsm-rsa-upload-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = var.gcp_key_file
  name     = local.gcp_connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.id
  name           = var.keyring
  project_id     = var.gcp_project
}

# Create a HSM-Luna network connection
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = var.hsm_hostname
  hsm_certificate = var.hsm_certificate
}

# Create a HSM-Luna connection
# is_ha_enabled must be true for more than one partition
resource "ciphertrust_hsm_connection" "hsm_connection" {
  hostname  = var.hsm_hostname
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = local.hsm_connection_name
  partitions {
    partition_label = var.hsm_partition_label
    serial_number   = var.hsm_partition_serial_number
  }
  partition_password = var.hsm_partition_password
  is_ha_enabled      = false
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}

# Create a HSM-Luna key
resource "ciphertrust_hsm_key" "hsm_key" {
  attributes   = ["CKA_WRAP", "CKA_UNWRAP", "CKA_ENCRYPT", "CKA_DECRYPT"]
  label        = local.key_name
  mechanism    = "CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 2048
}

# Upload the HSM-Luna key to Google Cloud
resource "ciphertrust_gcp_key" "gcp_rsa_key" {
  algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
  key_ring  = ciphertrust_gcp_keyring.keyring.id
  name      = local.key_name
  upload_key {
    source_key_identifier = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier       = "hsm-luna"
  }
}
output "gcp_rsa_key" {
  value = ciphertrust_gcp_key.gcp_rsa_key
}
