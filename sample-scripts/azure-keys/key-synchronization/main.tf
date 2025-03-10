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
  connection_name = "azure-connection-${lower(random_id.random.hex)}"
  sync_job_name   = "azure-sync-${lower(random_id.random.hex)}"
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

# Schedule synchronization of a vault
# Synchronization can also be scheduled for all vaults
resource "ciphertrust_scheduler" "sync_vaults" {
  cckm_synchronization_params {
    cloud_name = "AzureCloud"
    key_vaults = [ciphertrust_azure_vault.azure_vault.id]
  }
  name      = local.sync_job_name
  operation = "cckm_synchronization"
  run_at    = "0 9 * * sat"
}
output "sync_vaults" {
  value = ciphertrust_scheduler.sync_vaults
}
