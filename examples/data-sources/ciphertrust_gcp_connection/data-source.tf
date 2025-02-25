# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the GCP (Google Cloud Platform) connection.

terraform {
  # Specify required providers
  required_providers {
    ciphertrust = {
      # Source location for the CipherTrust provider
      source = "thalesgroup.com/oss/ciphertrust"
      # Version of the provider to be used
      version = "1.0.0"
    }
  }
}

# Configuration for the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance
  # Replace with the actual address of your CipherTrust instance
  address = "https://10.10.10.10"

  # Username to authenticate against the CipherTrust appliance
  username = "admin"

  # Password to authenticate against the CipherTrust appliance
  password = "SamplePassword@1"

  bootstrap = "no"
}

# Data source for retrieving GCP connection details
data "ciphertrust_gcp_connection_list" "example_gcp_connection" {
  # Filters to narrow down the GCP connections
  filters = {
    # The unique ID of the GCP connection to fetch
    id = "60f04cb1-4a48-4786-8965-39f2031518c4"
  }
  # Similarly can provide 'name', 'labels' etc to fetch the existing GCP connection
  # example for fetching an existing gcp connection with labels
  # filters = {
  #   labels = "key=value"
  # }
}

# Output the details of the GCP connection
output "gcp_connection_details" {
  # The value of the GCP connection details returned by the data source
  value = data.ciphertrust_gcp_connection_list.example_gcp_connection
}
