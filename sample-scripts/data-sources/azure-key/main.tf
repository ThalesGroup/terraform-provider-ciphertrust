terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.10-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "azure-connection-${lower(random_id.random.hex)}"
  key_name        = "azure-key-data-source-${lower(random_id.random.hex)}"
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
# Create an Azure key in the first vault
resource "ciphertrust_azure_key" "azure_key" {
  name  = local.key_name
  vault = ciphertrust_azure_vault.azure_vault.id
}
output "azure_key" {
  value = ciphertrust_azure_key.azure_key.id
}

# Get the key using the Azure key ID
data "ciphertrust_azure_key" "key_from_azure_key_id" {
  azure_key_id = ciphertrust_azure_key.azure_key.azure_key_id
}
output "key_from_azure_key_id" {
  value = data.ciphertrust_azure_key.key_from_azure_key_id.id
}

# Get the key using the key name and vault
data "ciphertrust_azure_key" "key_from_name_and_vault" {
  depends_on = [ciphertrust_azure_key.azure_key]
  key_vault  = format("%s::%s", var.vault_name, data.ciphertrust_azure_account_details.subscriptions.subscription_id)
  name       = local.key_name
}
output "key_from_name_and_vault" {
  value = data.ciphertrust_azure_key.key_from_name_and_vault.id
}

# Get the key using the key name, version and vault
data "ciphertrust_azure_key" "key_from_name_and_version_and_vault" {
  depends_on = [ciphertrust_azure_key.azure_key]
  key_vault  = format("%s::%s", var.vault_name, data.ciphertrust_azure_account_details.subscriptions.subscription_id)
  name       = local.key_name
  version    = "-1"
}
output "key_from_name_and_version_and_vault" {
  value = data.ciphertrust_azure_key.key_from_name_and_version_and_vault.id
}
