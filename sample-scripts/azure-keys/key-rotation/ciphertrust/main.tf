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
  connection_name   = "azure-connection-${lower(random_id.random.hex)}"
  key_name          = "cm-rotation-${lower(random_id.random.hex)}"
  rotation_job_name = "azure-cm-${lower(random_id.random.hex)}"
}

# Create an Azure connection
resource "ciphertrust_azure_connection" "azure_connection" {
  name = local.connection_name
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

# Create an EC key with scheduled rotation
resource "ciphertrust_azure_key" "azure_key" {
  enable_rotation {
    job_config_id = ciphertrust_scheduler.rotation_job.id
    key_source    = "ciphertrust"
  }
  key_type = "RSA"
  name     = local.key_name
  vault    = ciphertrust_azure_vault.azure_vault.id
}
output "key" {
  value = ciphertrust_azure_key.azure_key
}
