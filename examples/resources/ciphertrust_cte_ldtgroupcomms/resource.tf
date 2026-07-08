# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an LDT group communication service resource
# with the CipherTrust provider, including setting up service details.

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

# Add a resource of type LDT group communication service with the name test_lgs
resource "ciphertrust_cte_ldtgroupcomms" "lgs" {
  name        = "test_lgs"
  description = "Testing ldt comm group using Terraform"
  client_list = ["client1","client2"]
}

# Output the unique ID of the created LDT group communication service
output "lgs_id" {
    value = ciphertrust_cte_ldtgroupcomms.lgs.id
}