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
  key_name        = "key-${lower(random_id.random.hex)}"
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
resource "ciphertrust_azure_vault" "azure_vault_one" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = var.vault_name
}

# Add another vault
resource "ciphertrust_azure_vault" "azure_vault_two" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = var.premium_vault_name
}

# Create a key
resource "ciphertrust_azure_key" "original_key" {
  name  = local.key_name
  vault = ciphertrust_azure_vault.azure_vault_one.id
}
output "original_key" {
  value = ciphertrust_azure_key.original_key
}

# Restore key to a different vault
resource "ciphertrust_azure_key" "restored_key" {
  restore_key_id = ciphertrust_azure_key.original_key.key_id
  vault          = ciphertrust_azure_vault.azure_vault_two.id
}
output "restored_key" {
  value = ciphertrust_azure_key.restored_key
}
