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
  sync_job_name   = "gcp-sync-${lower(random_id.random.hex)}"
}

# Create an GCP connection
resource "ciphertrust_gcp_connection" "connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}

# Add a GCP keyring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.connection.name
  name           = var.keyring
  project_id     = var.gcp_project
}

# Schedule synchronization of some keyrings
# Synchronization can also be scheduled for all keyrings
resource "ciphertrust_scheduler" "sync_keyring" {
  cckm_synchronization_params {
    cloud_name = "gcp"
    key_rings  = [ciphertrust_gcp_keyring.keyring.id]
  }
  name      = local.sync_job_name
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
}
output "sync_keyring" {
  value = ciphertrust_scheduler.sync_keyring
}
