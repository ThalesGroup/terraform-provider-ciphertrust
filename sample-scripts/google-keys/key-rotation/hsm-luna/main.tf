terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.3-beta"
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
  key_name            = "gcp-rotation-hsm-${lower(random_id.random.hex)}"
  rotation_job_name   = "gcp-dsm-${lower(random_id.random.hex)}"
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

# Create scheduled rotation job to run every Saturday at 9 am
resource "ciphertrust_scheduler" "rotation_job" {
  cckm_key_rotation_params {
    cloud_name = "gcp"
  }
  name      = local.rotation_job_name
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}
output "rotation_job" {
  value = ciphertrust_scheduler.rotation_job
}

# Create a Google Cloud key with rotation enabled
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_2048_SHA256"
  enable_rotation {
    algorithm     = "RSA_DECRYPT_OAEP_4096_SHA512"
    job_config_id = ciphertrust_scheduler.rotation_job.id
    key_source    = "ciphertrust"
  }
  key_ring = ciphertrust_gcp_keyring.keyring.id
  name     = local.key_name
}
output "gcp_key" {
  value = ciphertrust_gcp_key.gcp_key
}
