# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the CTE clients.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre3"
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

# Data source for retrieving CTE clients details
data "ciphertrust_cte_clients_list" "data_client_list1" {
  # Filters to apply when retrieving the list of CTE clients
  filters = {
    # The name filter to specify which CTE clients to retrieve (replace with actual client names)
    name = "sjavlr89-sah-s3-test-cteu.sjcicd.com"
  }
}

output "cte_list" {
  # Output the list of CTE clients retrieved from the data source
  value = data.ciphertrust_cte_clients_list.data_client_list1.clients
}
