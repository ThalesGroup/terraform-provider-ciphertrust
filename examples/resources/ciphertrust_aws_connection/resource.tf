# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an AWS connection resource
# with the CipherTrust provider, including setting up AWS connection details,
# labels, and custom metadata.

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

# Define an AWS connection resource with CipherTrust
resource "ciphertrust_aws_connection" "aws_connection" {
  # Name of the AWS connection (unique identifier)
  name = "tf-aws-connection"

  # List of products associated with this AWS connection
  # In this case, it's related to backup/restore operations
  products = [
    "cckm"
  ]

  # Key ID of the AWS user.
  access_key_id = "ACCESS_KEY_ID"

  # Secret associated with the access key ID of the AWS user.
  secret_access_key = "SECRET_ACCESS_KEY"

  # Name of the cloud.
  cloud_name= "aws"

  # AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given. For aws, default region will be "us-east-1".
  aws_region = "us-east-1"

  # Description about the connection.
  description = "Terraform Generated"

  # Labels for categorizing the AWS connection
  labels = {
      "environment" = "devenv"
  }

  # Custom metadata for the AWS connection
  # This can be used to store additional information related to the AWS connection
  meta = {
      "custom_meta_key1" = "custom_value1"
      "customer_meta_key2" = "custom_value2"
  }
}

# Output the unique ID of the created AWS connection
output "aws_connection_id" {
  # The value will be the ID of the AWS connection resource
  value = ciphertrust_aws_connection.aws_connection.id
}

# Output the name of the created AWS connection
output "aws_connection_name" {
  # The value will be the name of the AWS connection resource
  value = ciphertrust_aws_connection.aws_connection.name
}
