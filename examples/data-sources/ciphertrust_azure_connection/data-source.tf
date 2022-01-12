# List vault information for a connection
data "ciphertrust_azure_connection" "vault_info" {
  azure_connection = "AzureConnectionName"
}
