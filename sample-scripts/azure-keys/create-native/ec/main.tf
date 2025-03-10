terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.9-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "azure_connection-${lower(random_id.random.hex)}"
  min_key_name    = "ec-min-params-${lower(random_id.random.hex)}"
  max_key_name    = "ec-max-params-${lower(random_id.random.hex)}"
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

# Minimum input parameters for an EC key
resource "ciphertrust_azure_key" "ec_key_min_params" {
  key_type = "EC"
  name     = local.min_key_name
  vault    = ciphertrust_azure_vault.azure_vault.id
}
output "ec_key_min_params" {
  value = ciphertrust_azure_key.ec_key_min_params
}

# Maximum input parameters for an EC key
resource "ciphertrust_azure_key" "ec_key_max_params" {
  curve           = "SECP256K1"
  enable_key      = false
  expiration_date = "2025-02-04T14:24:30Z"
  key_ops         = ["sign", "verify"]
  key_type        = "EC"
  name            = local.max_key_name
  tags = {
    TagKey1 = "TagValue1"
    TagKey2 = "TagValue2"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}
output "ec_key_max_params" {
  value = ciphertrust_azure_key.ec_key_max_params
}
