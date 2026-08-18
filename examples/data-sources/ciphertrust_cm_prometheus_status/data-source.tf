# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch the
# current status of the Prometheus metrics integration.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre11"
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

# Data source for retrieving the Prometheus metrics status. This is a singleton,
# no filters are needed.
data "ciphertrust_cm_prometheus_status" "example_prometheus_status" {}

# Output whether Prometheus metrics are enabled
output "prometheus_enabled" {
  value = data.ciphertrust_cm_prometheus_status.example_prometheus_status.enabled
}
