# Define the Terraform provider configuration block
terraform {
  required_providers {
    # The provider configuration for CipherTrust is sourced from 'thalesgroup.com/oss/ciphertrust'
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"  # Provider source
      version = "1.0.0"  # Version of the CipherTrust provider to use
    }
  }
}

# Define the CipherTrust provider block
provider "ciphertrust" {
  # The address of the CipherTrust server, where the API is hosted
  address = "https://10.10.10.10"  # Replace with the actual CipherTrust server URL

  # Username for authentication to the CipherTrust server
  username = "admin"  # Replace with your actual username

  # Password for authentication to the CipherTrust server
  password = "SamplePass_1"  # Replace with your actual password

  bootstrap = "no"
}

# Define a resource for managing the Prometheus integration in CipherTrust
resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  # This resource is used to enable or disable the Prometheus integration
  # 'enabled' is a boolean that determines whether Prometheus is enabled or not
  enabled = true  # Set to 'true' to enable, 'false' to disable
}

# Output block to display the enabled status of the Prometheus integration
output "prometheus" {
  # The output will show the 'enabled' attribute of the 'ciphertrust_cm_prometheus' resource
  value = ciphertrust_cm_prometheus.cm_prometheus.enabled  # The value is the 'enabled' status
}
