terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  azure_connection_name = "azure-connection-${lower(random_id.random.hex)}"
  hsm_connection_name   = "hsm-connection-${lower(random_id.random.hex)}"
  key_name              = "hsm-rotation-${lower(random_id.random.hex)}"
  rotation_job_name     = "azure-hsm-${lower(random_id.random.hex)}"
}

# Create an Azure connection
resource "ciphertrust_azure_connection" "azure_connection" {
  name = local.azure_connection_name
}

# Get Azure subscription
data "ciphertrust_azure_account_details" "subscriptions" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
}

# Add a vault
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = var.vault_name
}

# Create a HSM-Luna network server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = var.hsm_hostname
  hsm_certificate = var.hsm_certificate
}

# Create a HSM-Luna connection
resource "ciphertrust_hsm_connection" "hsm_connection" {
  hostname  = var.hsm_hostname
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = local.hsm_connection_name
  partitions {
    partition_label = var.hsm_partition_label
    serial_number   = var.hsm_partition_serial_number
  }
  partition_password = var.hsm_partition_password
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}

# Create scheduled rotation job to run every Saturday at 9 am
resource "ciphertrust_scheduler" "rotation_job" {
  cckm_key_rotation_params {
    cloud_name = "AzureCloud"
  }
  name      = local.rotation_job_name
  operation = "cckm_key_rotation"
  run_at    = "0 9 * * sat"
  run_on    = "any"
}
output "rotation_job" {
  value = ciphertrust_scheduler.rotation_job
}

# Retrieve details using the scheduler's name
data "ciphertrust_scheduler" "rotation_scheduler" {
  name = ciphertrust_scheduler.rotation_job.name
}
output "rotation_scheduler" {
  value = data.ciphertrust_scheduler.rotation_scheduler
}

# Create an RSA key with scheduled rotation
resource "ciphertrust_azure_key" "azure_key" {
  enable_rotation {
    hsm_partition_id = ciphertrust_hsm_partition.hsm_partition.id
    job_config_id    = data.ciphertrust_scheduler.rotation_scheduler.id
    key_source       = "hsm-luna"
  }
  key_type = "RSA-HSM"
  name     = local.key_name
  key_size = 2048
  vault    = ciphertrust_azure_vault.azure_vault.id
}
output "key" {
  value = ciphertrust_azure_key.azure_key
}
