# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an proxy resource
# with the CipherTrust provider, including setting up proxy details.

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

# Add a resource of type proxy
resource "ciphertrust_proxy" "proxie" {
  http_proxy = "user01:test12345@10.171.18.190:8080"
  https_proxy = "user02:Test12345@10.171.18.190:8081"
  no_proxy = ["127.0.0.1", "localhost"]
}

# Output the unique ID of the created proxy
output "proxie_id" {
    value = ciphertrust_proxy.proxie.id
}