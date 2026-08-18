# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about existing scheduled jobs.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre11"
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

# Data source for retrieving scheduled job details. Omitting 'filters' returns
# every scheduled job currently configured on the CipherTrust appliance.
data "ciphertrust_scheduler_list" "example_scheduler" {
  # filters = {
  #   operation = "database_backup"
  # }
}

# Output the details of the scheduled jobs
output "scheduler_details" {
  # The value of the scheduled job details returned by the data source
  value = data.ciphertrust_scheduler_list.example_scheduler
}
