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
  azure_connection_name = "azure-connection-${lower(random_id.random.hex)}"
  dsm_connection_name   = "dsm-connection-${lower(random_id.random.hex)}"
  key_name              = "dsm-upload-${lower(random_id.random.hex)}"
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

# Create a dsm connection
resource "ciphertrust_dsm_connection" "dsm_connection" {
  name = local.dsm_connection_name
  nodes {
    hostname    = var.dsm_ip
    certificate = var.dsm_certificate
  }
  password = var.dsm_password
  username = var.dsm_username
}

# Add a DSM domain
resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.dsm_connection.id
  domain_id      = var.dsm_domain
}

# Create a DSM RSA key
resource "ciphertrust_dsm_key" "dsm_key" {
  name        = local.key_name
  algorithm   = "RSA2048"
  domain      = ciphertrust_dsm_domain.dsm_domain.id
  extractable = true
  object_type = "asymmetric"
}
output "dsm_key" {
  value = ciphertrust_dsm_key.dsm_key
}

# Upload the DSM key to Azure
resource "ciphertrust_azure_key" "azure_key" {
  name  = local.key_name
  vault = ciphertrust_azure_vault.azure_vault.id
  upload_key {
    dsm_key_id      = ciphertrust_dsm_key.dsm_key.id
    source_key_tier = "dsm"
  }
}
output "azure_key" {
  value = ciphertrust_azure_key.azure_key
}
