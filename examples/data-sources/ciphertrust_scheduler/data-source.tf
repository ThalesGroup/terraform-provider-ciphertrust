# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the Ciphertrust Scheduler Job Configs.

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

# Data source for retrieving Scheduler Job Configs
data "ciphertrust_scheduler_list" "jobs" {
  filters = {
  # Filters to narrow down the Scheduler Jobs
    # The unique ID of the Job
    id = "60f04cb1-4a48-4786-8965-39f2031518c4"
  }
  # Similarly can provide 'name' 'operation' 'disabled' etc to fetch the existing Scheduler Job
  # Provide no filters and it will fetch all the scheduler jobs present in the provider
}

# Output the details of the Scheduler job
output "scheduler_jobs" {
  value = data.ciphertrust_scheduler_list.jobs
}
