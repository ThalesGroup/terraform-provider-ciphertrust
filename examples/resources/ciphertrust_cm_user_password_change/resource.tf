# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the updation of a User's password resource
# with the CipherTrust provider, including setting up user's previous and new password details.

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

  bootstrap = "yes"
}

# Update a resource of type CM User's password
resource "ciphertrust_cm_user_password_change" "pwd_change" {
    # The login name of the current user.
    username = "frank"

    # The own user's current password
    password = "ChangeMe101!"

    # The new password
    new_password = "ChangeMe201!"
}