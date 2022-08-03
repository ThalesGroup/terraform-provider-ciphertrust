terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta5"
    }
  }
}

provider "ciphertrust" {}

provider "azurerm" {
  features {}
}

resource "random_id" "random" {
  byte_length = 6
}

locals {
  connection_name = "connection-${lower(random_id.random.hex)}"
  key_name        = "key-${lower(random_id.random.hex)}"
}

data "azurerm_client_config" "current" {}

# Create a storage account in the same resource group and location as the vault
resource "azurerm_storage_account" "storage-account" {
  name                     = "terraform${lower(random_id.random.hex)}"
  resource_group_name      = var.vault_resource_group_name
  location                 = var.resource_group_location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  identity {
    type = "SystemAssigned"
  }
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

# Add an access policy to the vault for the storage account
resource "azurerm_key_vault_access_policy" "storage-account-policy" {
  key_vault_id       = ciphertrust_azure_vault.azure_vault.azure_vault_id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = azurerm_storage_account.storage-account.identity.0.principal_id
  key_permissions    = ["get", "create", "list", "restore", "recover", "unwrapkey", "wrapkey", "purge", "encrypt", "decrypt", "sign", "verify"]
  secret_permissions = ["get"]
}

# Create a CipherTrust key
resource "ciphertrust_azure_key" "key" {
  name     = local.key_name
  vault    = ciphertrust_azure_vault.azure_vault.id
  key_type = "RSA"
  depends_on = [
    azurerm_key_vault_access_policy.storage-account-policy,
  ]
}

# Configure storage account to use the key
resource "azurerm_storage_account_customer_managed_key" "customer-managed-key" {
  storage_account_id = azurerm_storage_account.storage-account.id
  key_vault_id       = ciphertrust_azure_vault.azure_vault.azure_vault_id
  key_name           = local.key_name
  # Wait for the policy resource
  depends_on = [
    azurerm_key_vault_access_policy.storage-account-policy,
  ]
}
