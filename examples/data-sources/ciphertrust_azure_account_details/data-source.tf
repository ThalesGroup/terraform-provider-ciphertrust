# Create an Azure connection 
resource "ciphertrust_azure_connection" "azure_connection" {
  name          = "connection-name"
  client_id     = "azure-client-id"
  client_secret = "azure-client-secret"
  tenant_id     = "azure-tenant-id"
}

data "ciphertrust_azure_account_details" "subscriptions" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
}

resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = data.ciphertrust_azure_account_details.subscriptions.subscription_id
  name             = "azure-vault"
}
