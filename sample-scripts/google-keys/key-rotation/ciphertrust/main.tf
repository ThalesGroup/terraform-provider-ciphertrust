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
  connection_name   = "gcp-connection-${lower(random_id.random.hex)}"
  key_name          = "gcp-rotation-cm-${lower(random_id.random.hex)}"
  rotation_job_name = "gcp-cm-${lower(random_id.random.hex)}"
}

# Create an GCP connection
resource "ciphertrust_gcp_connection" "connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.connection.name
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

# Create a symmetric key with rotation enabled
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  enable_rotation {
    algorithm     = "GOOGLE_SYMMETRIC_ENCRYPTION"
    job_config_id = ciphertrust_scheduler.rotation_job.id
    key_source    = "ciphertrust"
  }
  key_ring = ciphertrust_gcp_keyring.keyring.id
  name     = local.key_name
}
output "gcp_key" {
  value = ciphertrust_gcp_key.gcp_key
}
