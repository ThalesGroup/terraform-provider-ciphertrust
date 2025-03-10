# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a Syslog connection resource
# with the CipherTrust provider, including setting up Syslog connection details.

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

# Add a resource of type Syslog connection with the host example.syslog.com
resource "ciphertrust_syslog" "syslog_1" {
    host = "example.syslog.com"
    transport = "udp"
}

# Output the unique ID of the created syslog connection resource
output "syslog_connection_value" {
	value = ciphertrust_syslog.syslog_1.host
}