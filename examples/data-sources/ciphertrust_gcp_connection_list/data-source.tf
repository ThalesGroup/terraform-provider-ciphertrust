# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about GCP connections.

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

# Data source for retrieving GCP connection details
data "ciphertrust_gcp_connection_list" "example_gcp_connection" {
  # Filters to narrow down the GCP connections
  filters = {
    # The name of the GCP connection to fetch
    name = "gcp-connection"
  }
  # Similarly can provide 'id', 'products', 'meta_contains' etc to fetch the existing GCP connection
}

# Output the details of the GCP connection. Marked sensitive because the
# nested 'private_key_id' attribute is a sensitive field.
output "gcp_connection_details" {
  value     = data.ciphertrust_gcp_connection_list.example_gcp_connection
  sensitive = true
}
