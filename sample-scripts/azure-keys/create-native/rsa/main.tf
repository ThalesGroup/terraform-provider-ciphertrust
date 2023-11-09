terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.2-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name  = "azure-connection-${lower(random_id.random.hex)}"
  rsa_min_key_name = "rsa-min-params-${lower(random_id.random.hex)}"
  rsa_max_key_name = "rsa-max-params-${lower(random_id.random.hex)}"
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

# Minimum input parameters for an RSA key
resource "ciphertrust_azure_key" "rsa_key_min_params" {
  name  = local.rsa_min_key_name
  vault = ciphertrust_azure_vault.azure_vault.id
}
output "rsa_key_min_params" {
  value = ciphertrust_azure_key.rsa_key_min_params
}

# Maximum input parameters for an RSA key
resource "ciphertrust_azure_key" "rsa_key_max_params" {
  activation_date = "2023-02-07T21:24:52Z"
  enable_key      = true
  expiration_date = "2025-02-08T21:24:52Z"
  key_ops         = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
  key_size        = 4096
  name            = local.rsa_max_key_name
  tags = {
    TagKey1 = "TagValue1"
    TagKey2 = "TagValue2"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}
output "rsa_key_max_params" {
  value = ciphertrust_azure_key.rsa_key_max_params
}
