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
  key_name              = "cm-upload-${lower(random_id.random.hex)}"
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

# Create a CipherTrust Manager Key
resource "ciphertrust_cm_key" "cm_key" {
  algorithm = "RSA"
  name      = local.key_name
  key_size  = 4096
}
output "cm_key" {
  value = ciphertrust_cm_key.cm_key
}

# Upload it to Azure
resource "ciphertrust_azure_key" "azure_key" {
  key_ops = ["encrypt", "decrypt"]
  name    = local.key_name
  vault   = ciphertrust_azure_vault.azure_vault.id
  upload_key {
    local_key_id = ciphertrust_cm_key.cm_key.id
  }
}
output "key" {
  value = ciphertrust_azure_key.azure_key
}
