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
  connection_name = "azure-connection-${lower(random_id.random.hex)}"
}

# Create an Azure connection
resource "ciphertrust_azure_connection" "azure_connection" {
  name = local.connection_name
}
output "azure_connection_id" {
  value = ciphertrust_azure_connection.azure_connection.id
}

# Get Azure subscription
data "ciphertrust_azure_account_details" "subscriptions" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
}
output "subscriptions" {
  value = data.ciphertrust_azure_account_details.subscriptions
}

# Add a vault
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = var.vault_name
}
output "azure_vault" {
  value = ciphertrust_azure_vault.azure_vault
}
