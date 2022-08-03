# Create an Azure connection
resource "ciphertrust_azure_connection" "azure_connection" {
  name          = "connection-name"
  client_id     = "azure-client-id"
  client_secret = "azure-client-secret"
  tenant_id     = "azure-tenant-id"
}

# Add a vault
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = "azure-subscription-id"
  name             = "azure-vault-name"
}

# Get the Azure connection details including the vaults
data "ciphertrust_azure_connection" "connection_details" {
  azure_connection = "connection-name"
}
