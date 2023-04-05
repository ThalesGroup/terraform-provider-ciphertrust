# Get the Azure connection details including the vaults
data "ciphertrust_azure_connection" "connection_details" {
  azure_connection = "connection-name"
}
