# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE client resource
# with the CipherTrust provider, including setting up CTE client details.

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

# Add a resource of type CTE client with the name test_client
resource "ciphertrust_cte_client" "cte_client" {
  # Name to uniquely identify the client.
  name = "test_client"

  # Password creation method for the client. Valid values are MANUAL and GENERATE.
  password_creation_method = "GENERATE"

  # Description of client
  description = "Created via Terraform"

  # Whether client's registration with the CipherTrust Manager is allowed.
  registration_allowed = true

  # Whether communication with the client is enabled.
  communication_enabled = true

  # Type of CTE Client. Valid values are CTE-U and FS.
  client_type = "FS"
}

# Output the unique ID of the created CTE Client
output "cte_client_id" {
    # The value will be the ID of the CTE client resource
    value = ciphertrust_cte_client.cte_client.id
}