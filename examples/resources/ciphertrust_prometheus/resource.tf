# Define the Terraform provider configuration block
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
