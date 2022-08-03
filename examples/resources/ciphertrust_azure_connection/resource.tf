# Create an Azure connection without using environment variables
resource "ciphertrust_azure_connection" "azure_connection" {
  name          = "connection-name"
  client_id     = "azure-client-id"
  client_secret = "azure-client-secret"
  tenant_id     = "azure-tenant-id"
}

# Create an Azure connection using the ARM_CLIENT_ID, ARM_CLIENT_SECRET and ARM_TENANT_ID environment variables
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "connection-name"
}

# Create a ciphertrust_azure_vault resource and assign it to the connection
resource "ciphertrust_azure_vault" "azure_vault" {
  azure_connection = ciphertrust_azure_connection.azure_connection.name
  subscription_id  = "azure-subscription-id"
  name             = "azure-vault-name"
}

# Create an Azure key
resource "ciphertrust_azure_key" "azure_key" {
  name     = "key-name"
  vault    = ciphertrust_azure_vault.azure_vault.id
}
