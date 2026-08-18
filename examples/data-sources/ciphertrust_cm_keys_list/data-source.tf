# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about existing keys.

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

# Data source for retrieving key details
data "ciphertrust_cm_keys_list" "example_keys" {
  # Filters to narrow down the keys
  filters = {
    # The algorithm of the keys to fetch. CipherTrust Manager matches this
    # value case-sensitively against the stored algorithm (e.g. "AES", not
    # "aes"), even though the create-time algorithm attribute is lowercase.
    algorithm = "AES"
  }
  # Similarly can provide 'name', 'id', 'state', 'usageMask' etc to fetch existing keys
  # example for fetching an existing key by name
  # filters = {
  #   name = "my-key"
  # }
}

# Output the details of the keys
output "keys_details" {
  # The value of the key details returned by the data source
  value = data.ciphertrust_cm_keys_list.example_keys
}
