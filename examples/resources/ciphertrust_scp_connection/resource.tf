# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an SCP connection resource
# with the CipherTrust provider, including setting up SCP connection details,
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

# Define an SCP connection resource with CipherTrust
resource "ciphertrust_scp_connection" "scp_connection" {
  # Name of the SCP connection (unique identifier)
  name = "scp-connection"

  # List of products associated with this SCP connection
  # In this case, it's related to backup/restore operations
  products = [
    "backup/restore"
  ]

  # Description of the SCP connection
  description = "a description of the connection"

  # Host IP address or domain of the SCP server
  host = "10.10.10.10"

  # Port used for SCP communication (default SCP port is 22)
  port = 22

  # Username for authentication on the SCP server
  username = "user"

  # Authentication method to be used, here it's set to "Password"
  auth_method = "Password"

  # Password for the SCP server authentication
  password = "password"

  # Path on the remote server to store or retrieve files
  path_to = "/home/path/to/directory/"

  # Protocol used for SCP connection (can be sftp, scp, etc.)
  protocol = "sftp"

  # Public SSH key for authentication, if using key-based authentication
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNxnOBfBVU4L3fQBVWK71CdoHXmFNxkD0lFYDagM8etytGxRMQeOSeARUYQA+xC/8ig+LHimQ97L0XPSCvTr/XbXxOYBOdGHFqr1o6QwmSBABoPz0fvfCHaipAdwGlfS50aDbCWYZSd9UX6stOazCPdQ9wiiGD0+wYmagxBtrBlzrXiXKV3q+GNr6iIlejsv2aK"

  # Labels for categorizing the SCP connection
  labels = {
    "environment" = "devenv"
  }

  # Custom metadata for the SCP connection
  # This can be used to store additional information related to the SCP connection
  meta = {
    "custom_meta_key1" = "custom_value1"  # Example custom metadata key-value pair
    "customer_meta_key2" = "custom_value2"  # Another custom metadata entry
  }
}

# Output the unique ID of the created SCP connection
output "scp_connection_id" {
  # The value will be the ID of the SCP connection resource
  value = ciphertrust_scp_connection.scp_connection.id
}

# Output the name of the created SCP connection
output "scp_connection_name" {
  # The value will be the name of the SCP connection resource
  value = ciphertrust_scp_connection.scp_connection.name
}
