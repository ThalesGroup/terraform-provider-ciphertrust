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
  connection_name  = "azure-connection-${lower(random_id.random.hex)}"
  rsa_hsm_key_name = "rsa-hsm-${lower(random_id.random.hex)}"
}

# Create an Azure connection
resource "ciphertrust_azure_connection" "azure_connection" {
  name = local.connection_name
}

# Get Azure subscription
data "ciphertrust_azure_account_details" "subscriptions" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
}

# Add a premium vault
resource "ciphertrust_azure_vault" "premium_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = var.premium_vault_name
}

# Create a hsm backed RSA-HSM BYOK KEK
resource "ciphertrust_azure_key" "azure_rsa_hsm_key" {
  key_ops  = ["import"]
  key_type = "RSA-HSM"
  name     = local.rsa_hsm_key_name
  vault    = ciphertrust_azure_vault.premium_vault.id
}
output "azure_rsa_hsm_key" {
  value = ciphertrust_azure_key.azure_rsa_hsm_key
}
