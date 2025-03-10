# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a domain resource
# with the CipherTrust provider, including setting up domain details
# and custom metadata.

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

# Add a resource of type CM Domain with the name domain_tf
resource "ciphertrust_domain" "domain" {
  # The name of the domain
  name = "domain_tf"

  # List of administrators for the domain
  admins = ["admin"]

  # To allow user creation and management in the domain, set it to true.
  allow_user_management = false

  # Optional end-user or service data stored with the domain.
  meta_data = {
      "abc": "xyz"
  }
}

# Output the unique ID of the created CM domain
output "domain_id" {
	value = ciphertrust_domain.domain.id
}