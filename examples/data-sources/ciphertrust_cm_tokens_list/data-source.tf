# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about existing client registration tokens.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.1"
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

# Data source for retrieving registration token details. Omitting 'filters'
# returns every registration token currently on the CipherTrust appliance.
data "ciphertrust_cm_tokens_list" "example_tokens" {
  # filters = {
  #   labels = "key1=value1,key2=value2"
  # }
}

# Output the details of the registration tokens. Marked sensitive because the
# nested 'token' attribute is a sensitive field.
output "tokens_details" {
  value     = data.ciphertrust_cm_tokens_list.example_tokens
  sensitive = true
}
