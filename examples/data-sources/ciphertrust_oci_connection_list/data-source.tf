# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about Oracle OCI connections.

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

# Data source for retrieving Oracle OCI connection details
data "ciphertrust_oci_connection_list" "example_oci_connection" {
  # Filters to narrow down the Oracle OCI connections
  filters = {
    # The unique ID of the Oracle OCI connection to fetch
    id = "88a90d8f-05b5-419f-bbe9-2dc3aa8ec216"
  }
  # Similarly can provide 'name', 'labels' etc to fetch the existing Oracle OCI connection
  # example for fetching an existing oci connection with labels
  # filters = {
  #   labels = "key=value"
  # }
}

# Output the details of the Oracle OCI connection
output "oci_connection_details" {
  # The value of the Oracle OCI connection details returned by the data source
  value = data.ciphertrust_oci_connection_list.example_oci_connection
}
