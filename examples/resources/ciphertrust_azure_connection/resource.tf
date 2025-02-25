# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an azure connection resource
# with the CipherTrust provider, including setting up azure connection details,
# labels, and custom metadata.

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
  password = "SamplePassword@1"

  bootstrap = "no"
}

# Define an azure connection resource with CipherTrust
resource "ciphertrust_azure_connection" "azure_connection" {
  # Name of the azure connection (unique identifier)
  name = "azure-connection"

  # Unique identifier for azure application
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"

  # Tenant ID for azure application
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"

  # Secret key for the azure application
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"

  # Name of the azure cloud
  cloud_name= "AzureCloud"

  # List of products associated with this azure connection
  # In this case, it's related to backup/restore operations
  products = [
    "cckm"
  ]

  # Description of the azure connection
  description = "a description of the connection"

  # Labels for categorizing the azure connection
  labels = {
    "environment" = "devenv"
  }

  # Custom metadata for the azure connection
  # This can be used to store additional information related to the azure connection
  meta = {
    "custom_meta_key1" = "custom_value1"  # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2"  # Another custom metadata entry
  }
}

# Output the unique ID of the created azure connection
output "azure_connection_id" {
  # The value will be the ID of the azure connection resource
  value = ciphertrust_azure_connection.azure_connection.id
}

# Output the name of the created azure connection
output "azure_connection_name" {
  # The value will be the name of the azure connection resource
  value = ciphertrust_azure_connection.azure_connection.name
}
