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

# Data source to fetch the status of the Prometheus configuration
data "ciphertrust_cm_prometheus_status" "status" {
  depends_on = [ciphertrust_cm_prometheus.cm_prometheus]
}

# Output the fetched status from the Prometheus data source
output "prometheus_status" {
  # The value is taken from the 'status' field of the 'ciphertrust_cm_prometheus_status' data source
  value = data.ciphertrust_cm_prometheus_status.status
}
