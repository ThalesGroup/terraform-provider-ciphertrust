# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the SCP (Secure Copy Protocol) connection.

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

# Data source for retrieving SCP connection details
data "ciphertrust_scp_connection_list" "example_scp_connection" {
  # Filters to narrow down the SCP connections
  filters = {
    # The unique ID of the SCP connection to fetch
    id = "60f04cb1-4a48-4786-8965-39f2031518c4"
  }
  # Similarly can provide 'name' 'protocol' 'labels' etc to fetch the existing SCP connection
  # example for fetching an existing scp connection with labels
  # filters = {
  #   labels = "key=value"
  # }
}

# Output the details of the SCP connection
output "scp_connection_details" {
  # The value of the SCP connection details returned by the data source
  value = data.ciphertrust_scp_connection_list.example_scp_connection
}
