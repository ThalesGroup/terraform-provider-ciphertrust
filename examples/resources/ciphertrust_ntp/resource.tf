# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an NTP resource
# with the CipherTrust provider, including setting up NTP host details.

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
  password = "ChangeMe101!"

  bootstrap = "no"
}

# Add a resource of type NTP server with the host time1.google.com
resource "ciphertrust_ntp" "ntp_server_1" {
  # The hostname or IP address of the NTP server.
  host = "time1.google.com"
}

# Output the unique ID of the created NTP resource
output "ntp_server_id" {
	value = ciphertrust_ntp.ntp_server_1.id
}