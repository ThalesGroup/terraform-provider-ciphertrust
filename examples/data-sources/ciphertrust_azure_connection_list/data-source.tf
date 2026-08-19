# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about Azure connections.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.1"
    }
  }
}

# Configure the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance (replace with the actual address)
  address = "https://10.10.10.10"

  # Username for authenticating with the CipherTrust appliance
  username = "admin"

  # Password for authenticating with the CipherTrust appliance
  password = "ChangeMe101!"
}

# Data source for retrieving Azure connection details
data "ciphertrust_azure_connection_list" "example_azure_connection" {
  # Filters to narrow down the Azure connections
  filters = {
    # The name of the Azure connection to fetch
    name = "azure-connection"
  }
  # Similarly can provide 'id', 'cloud_name', 'products', 'meta_contains' etc to fetch the existing Azure connection
  # example for fetching an existing Azure connection by cloud_name
  # filters = {
  #   cloud_name = "Azure"
  # }
}

# Output the details of the Azure connection. Marked sensitive because the
# nested 'client_secret' attribute is a sensitive field.
output "azure_connection_details" {
  value     = data.ciphertrust_azure_connection_list.example_azure_connection
  sensitive = true
}
