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

# Data source for retrieving CTE Profiles
data "ciphertrust_cte_profiles" "example" {
}

output "cte_profiles" {
  # Outputs CTE Profiles retrieved from the data source
  value = data.ciphertrust_cte_profiles.example.cte_profiles
}
