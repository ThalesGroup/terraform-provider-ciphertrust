# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an GCP connection resource
# with the CipherTrust provider, including setting up GCP connection details,
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



# Define an GCP connection resource with CipherTrust
resource "ciphertrust_gcp_connection" "gcp_connection" {
  # Name of the GCP connection (unique identifier)
  name        = "gcp-connection"

  # List of products associated with this GCP connection
  # In this case, it's related to cckm
  products = [
    "cckm"
  ]

  # The contents of private key file of a GCP service account.
  key_file    = "{\"type\":\"service_account\",\"private_key_id\":\"y437c51g956b8ab4908yb41541262a2fa3b0f84f\",\"private_key\":\"-----BEGIN RSA PRIVATE KEY-----\\n.....\\n-----END RSA PRIVATE KEY-----\\n\\n\",\"client_email\":\"test@some-project.iam.gserviceaccount.com\"}"

  # Name of the cloud. Default value is gcp.
  cloud_name  = "gcp"

  # Description of the GCP connection
  description = "connection description"

  # Labels for categorizing the GCP connection
  labels = {
    "environment" = "devenv"
  }

  # Custom metadata for the GCP connection
  # This can be used to store additional information related to the GCP connection
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }

}

# Output the unique ID of the created GCP connection
output "gcp_connection_id" {
  # The value will be the ID of the GCP connection resource
  value = ciphertrust_gcp_connection.gcp_connection.id
}

# Output the name of the created GCP connection
output "gcp_connection_name" {
  # The value will be the name of the GCP connection resource
  value = ciphertrust_gcp_connection.gcp_connection.name
}