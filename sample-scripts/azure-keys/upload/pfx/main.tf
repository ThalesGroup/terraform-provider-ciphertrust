terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.11.2"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "azure-connection-${lower(random_id.random.hex)}"
  key_name        = "pfx-upload-${lower(random_id.random.hex)}"
}

# Create an Azure connection
resource "ciphertrust_azure_connection" "azure_connection" {
  name = local.key_name
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

# Upload a pfx file to Azure
resource "ciphertrust_azure_key" "azure_key" {
  name = local.key_name
  upload_key {
    pfx             = var.pfx_file
    pfx_password    = var.pfx_pwd
    source_key_tier = "pfx"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}
output "key" {
  value = ciphertrust_azure_key.azure_key
}
