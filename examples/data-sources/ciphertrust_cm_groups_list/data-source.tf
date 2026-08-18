# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about existing user groups.

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

# Data source for retrieving group details
data "ciphertrust_cm_groups_list" "example_groups" {
  # Filters to narrow down the groups
  filters = {
    # The name of the group to fetch
    name = "Key Users"
  }
  # Similarly can provide 'users', 'connection', 'clients' etc to fetch existing groups
}

# Output the details of the groups
output "groups_details" {
  # The value of the group details returned by the data source
  value = data.ciphertrust_cm_groups_list.example_groups
}
