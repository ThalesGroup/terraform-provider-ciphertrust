terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.5-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  azure_connection_name = "azure-connection-${lower(random_id.random.hex)}"
  hsm_connection_name   = "hsm-connection-${lower(random_id.random.hex)}"
  key_name              = "hsm-upload-${lower(random_id.random.hex)}"
  exportable_key_name  = "hsm-upload-exportable-${lower(random_id.random.hex)}"
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

# Create a hsm network server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = var.hsm_hostname
  hsm_certificate = var.hsm_certificate
}

# Add create a hsm connection
resource "ciphertrust_hsm_connection" "hsm_connection" {
  hostname  = var.hsm_hostname
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = local.hsm_connection_name
  partitions {
    partition_label = var.hsm_partition_label
    serial_number   = var.hsm_partition_serial_number
  }
  partition_password = var.hsm_partition_password
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}

# Create a hsm key
resource "ciphertrust_hsm_key" "hsm_key" {
  attributes   = ["CKA_WRAP", "CKA_UNWRAP", "CKA_ENCRYPT", "CKA_DECRYPT"]
  label        = local.key_name
  mechanism    = "CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 2048
}
output "hsm_key" {
  value = ciphertrust_hsm_key.hsm_key
}

# Upload the hsm key to Azure
resource "ciphertrust_azure_key" "azure_key" {
  name = local.key_name
  upload_key {
    hsm_key_id      = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier = "hsm-luna"
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}
output "azure_key" {
  value = ciphertrust_azure_key.azure_key
}

# It's also possible to create an exportable key in Azure when uploading a key from a hsm-luna
resource "ciphertrust_azure_key" "azure_exportable_key" {
  name = local.exportable_key_name
  upload_key {
    hsm_key_id      = ciphertrust_hsm_key.hsm_key.private_key_id
    source_key_tier = "hsm-luna"
    exportable      = "true"
    release_policy  =  <<-EOT
    {
      "anyOf": [{
        "anyOf": [{
          "claim": "lzxdwiqk24k24",
          "equals": "true"
        }],
        "authority": "https://lzxdwiqk24jkh.ncus.attest.azure.net"
      }],
      "version": "1.0.0"
    }
    EOT
  }
  vault = ciphertrust_azure_vault.azure_vault.id
}
output "azure_exportable_key" {
  value = ciphertrust_azure_key.azure_exportable_key
}
