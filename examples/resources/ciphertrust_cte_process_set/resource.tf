# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an SCP connection resource
# with the CipherTrust provider, including setting up SCP connection details,
# labels, and custom metadata.

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

# Add a resource of type CTE Process Set with the name process_set
resource "ciphertrust_cte_process_set" "process_set" {
    name = "process_set"
    description = "Process set test"
    processes = [
      {
        directory = "/opt/temp1"
        file = "*"
        signature = "demo"
        labels = {
            key1 = "value1"
        }
      }
    ]
}

# Output the unique ID of the created CTE Process Set
output "process_set_id" {
    # The value will be the ID of the CTE Process Set resource
    value = ciphertrust_cte_process_set.process_set.id
}

# Output the name of the created CTE Process Set
output "process_set_name" {
    # The value will be the name of the CTE Process Set resource
    value = ciphertrust_cte_process_set.process_set.name
}