# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the Azure connection.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre3"
    }c
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
    # The unique ID of the Azure connection to fetch
    id = "88a90d8f-05b5-419f-bbe9-2dc3aa8ec216"
  }
  # Similarly can provide 'name', 'labels' etc to fetch the existing Azure connection
  # example for fetching an existing azure connection with labels
  # filters = {
  #   labels = "key=value"
  # }
}

# Output the details of the Azure connection
output "azure_connection_details" {
  # The value of the Azure connection details returned by the data source
  value = data.ciphertrust_azure_connection_list.example_azure_connection
}
