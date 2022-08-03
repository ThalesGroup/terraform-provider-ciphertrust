# This resource requires an ciphertrust_azure_connection resource
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "connection-name"
}

# Create a vault resource without using the ciphertrust_azure_account_details data-source and assign it to the connection
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = "subscription-id"
  name             = "azure-vault-name"
}

# Create a vault resource using the ciphertrust_azure_account_details data-source and assign it to the connection
data "ciphertrust_azure_account_details" "subscriptions" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  display_name     = "subscription-display-name"
}
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = "azure-vault-name"
}

# Create an Azure key
resource "ciphertrust_azure_key" "azure_key" {
  name  = "key-name"
  vault = ciphertrust_azure_vault.azure_vault.id
}
