# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the CTE ProcessSets.

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

# Data source for retrieving ProcessSets
data "ciphertrust_cte_process_sets" "example" {
}

output "process_sets" {
  # Outputs the Process Sets retrieved from the data source
  value = data.ciphertrust_cte_process_sets.example.process_sets
}
