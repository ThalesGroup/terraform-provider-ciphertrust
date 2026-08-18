# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about SCP connections.

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

# Data source for retrieving SCP connection details
data "ciphertrust_scp_connection_list" "example_scp_connection" {
  # Filters to narrow down the SCP connections
  filters = {
    # The protocol of the SCP connection to fetch
    protocol = "sftp"
  }
  # Similarly can provide 'id', 'name', 'products' etc to fetch the existing SCP connection
  # example for fetching an existing SCP connection by name
  # filters = {
  #   name = "scp-connection"
  # }
}

# Output the details of the SCP connection. Marked sensitive because the
# nested 'password' attribute is a sensitive field.
output "scp_connection_details" {
  value     = data.ciphertrust_scp_connection_list.example_scp_connection
  sensitive = true
}
