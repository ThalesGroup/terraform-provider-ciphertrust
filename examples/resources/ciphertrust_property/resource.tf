# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the updation of a CipherTrust Manager property resource
# with the CipherTrust provider, including setting up property details.

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

# Add a resource of type CipherTrust Manager property with the name ENABLE_RECORDS_DB_STORE
resource "ciphertrust_property" "property_1" {
    name = "ENABLE_RECORDS_DB_STORE"
    value = "false"
}

# Output the name of the updated CM property
output "cm_property_name" {
	value = ciphertrust_property.property_1.name
}