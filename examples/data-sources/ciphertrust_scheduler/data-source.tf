# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the Ciphertrust Scheduler Job Configs.

terraform {
  # Specify required providers
  required_providers {
    ciphertrust = {
      # Source location for the CipherTrust provider
      source = "thalesgroup.com/oss/ciphertrust"
      # Version of the provider to be used
      version = "1.0.0"
    }
  }
}

# Configuration for the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance
  # Replace with the actual address of your CipherTrust instance
  address = "https://10.10.10.10"

  # Username to authenticate against the CipherTrust appliance
  username = "admin"

  # Password to authenticate against the CipherTrust appliance
  password = "SamplePassword@1"

  bootstrap = "no"
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
