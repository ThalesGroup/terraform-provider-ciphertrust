# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a Group resource
# with the CipherTrust provider, including setting up group details.

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

# Add a resource of type CM Group with the name TestGroup
resource "ciphertrust_groups" "testGroup" {
  # Name of the group to be created on CM
  name = "TestGroup"
}

# Output the name of the created CM group
output "group_name" {
    # The value will be the name of the CM group
    value = ciphertrust_groups.testGroup.name
}