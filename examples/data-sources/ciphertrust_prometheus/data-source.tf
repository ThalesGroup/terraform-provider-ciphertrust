terraform {
  required_providers {
    # Defining the 'ciphertrust' provider, which will be sourced from thalesgroup.com
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"  # Source of the provider
      version = "1.0.0"  # Version of the provider to use
    }
  }
}

# Define the CipherTrust provider configuration
provider "ciphertrust" {
  # Address of the CipherTrust server where the API is hosted
  address = "https://10.10.10.10"  # Replace with your CipherTrust server address

  # The username used to authenticate with the CipherTrust server
  username = "admin"  # Replace with your actual username

  # The password used to authenticate with the CipherTrust server
  password = "SamplePassword_1"  # Replace with your actual password

  bootstrap = "no"
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
