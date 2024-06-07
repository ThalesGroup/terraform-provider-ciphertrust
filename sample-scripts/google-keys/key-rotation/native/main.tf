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
  gcp_connection_name = "gcp-connection-${lower(random_id.random.hex)}"
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

# Create an asymmetric key with rotation enabled
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_2048_SHA256"
  enable_rotation {
    job_config_id = ciphertrust_scheduler.rotation_job.id
    key_source    = "native"
  }
  key_ring = ciphertrust_gcp_keyring.keyring.id
  name     = local.key_name
}

output "gcp_key" {
  value = ciphertrust_gcp_key.gcp_key
}

output "gcp_key_id" {
  value = ciphertrust_gcp_key.gcp_key.id
}
