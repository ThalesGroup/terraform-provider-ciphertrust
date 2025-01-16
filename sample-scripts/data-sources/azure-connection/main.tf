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
  connection_name = "azure-connection-${lower(random_id.random.hex)}"
  key_name        = "cm-azure-key-data-source-${lower(random_id.random.hex)}"
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

# Add a vault
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = var.vault_name
}

# Get Azure connection details including vaults for the connection
data "ciphertrust_azure_connection" "connection_data" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  depends_on       = [ciphertrust_azure_vault.azure_vault]
}
output "connection_data" {
  value = data.ciphertrust_azure_connection.connection_data
}

# Create a key using datasource output
resource "ciphertrust_azure_key" "azure_key" {
  name     = local.key_name
  key_type = "RSA"
  vault    = data.ciphertrust_azure_connection.connection_data.vaults[ciphertrust_azure_vault.azure_vault.name]
}
output "azure_key_id" {
  value = ciphertrust_azure_key.azure_key.id
}
