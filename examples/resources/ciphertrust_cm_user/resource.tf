# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a user resource
# with the CipherTrust provider, including setting up user details.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "thalesgroup.com/oss/ciphertrust"
      # Version of the provider to use
      version = "1.0.0"
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

  bootstrap = "no"
}

# Add a resource of type CM User with the username frank
resource "ciphertrust_cm_user" "sample_user" {
  # Full name of the user
  name="frank"
  # E-mail of the user
  email="frank@local"
  # The login name of the user
  username="frank"
  # The password used to secure the users account
  password="ChangeIt01!"
}

# Output the unique ID of the created User
output "user_id" {
	value = ciphertrust_cm_user.sample_user.id
}

# Output the username
output "username" {
    value = ciphertrust_cm_user.sample_user.username
}