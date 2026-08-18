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

# Create a user that will be a member of the group
resource "ciphertrust_user" "cckm_user" {
  username = "test-cckm-user"
  password = "ChangeMe101!"
}

# Add a resource of type CM Group with the name TestGroup
resource "ciphertrust_groups" "testGroup" {
  # Name of the group to be created on CM
  name = "TestGroup"

  # Optional: set of user IDs that should be members of this group.
  # Users in the set are added; users removed from the set are removed.
  # Omit user_ids to leave membership unmanaged by Terraform.
  user_ids = [ciphertrust_user.cckm_user.id]
}

# Output the name of the created CM group
output "group_name" {
  # The value will be the name of the CM group
  value = ciphertrust_groups.testGroup.name
}