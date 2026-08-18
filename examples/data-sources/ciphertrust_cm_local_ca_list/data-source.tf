# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about local certificate authorities.

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

# Data source for retrieving local CA details
data "ciphertrust_cm_local_ca_list" "example_local_cas" {
  # Filters to narrow down the local CAs
  filters = {
    # Only fetch CAs in the active state
    state = "active"
  }
  # Similarly can provide 'id', 'subject', 'issuer', 'cert' etc to fetch existing local CAs
  # example for fetching an existing local CA by subject
  # filters = {
  #   subject = "/C=US/ST=TX/L=Austin/O=CipherTrust/CN=CA"
  # }
}

# Output the details of the local CAs
output "local_ca_details" {
  # The value of the local CA details returned by the data source
  value = data.ciphertrust_cm_local_ca_list.example_local_cas
}
