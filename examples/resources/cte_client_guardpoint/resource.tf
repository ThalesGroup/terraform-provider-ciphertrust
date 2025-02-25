# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE guardpoint resource
# with the CipherTrust provider, including setting up guardpoint details.

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

# Add a resource of type CTE guardpoint to guard paths /test1 and /test2
resource "ciphertrust_cte_guardpoint" "dir_auto_gp" {
  # List of GP paths
  guard_paths = ["/test1", "/test2"]

  # IP Address/hostname/ID of client.
  client_id = "243b14ec-2251-449d-9ada-6fb1f8e6a414"

  guard_point_params = {
    # Type of the GuardPoint. The valid values are “directory_auto”, “directory_manual”, “rawdevice_manual”, “rawdevice_auto”, “cloudstorage_auto”, “cloudstorage_manual”, or "ransomware_protection".
    guard_point_type = "directory_auto"

    # Guard Enabled
    guard_enabled = true

    # ID of the policy applied with this GuardPoint.
    policy_id = "00000000-0000-0000-0000-000000000000"
  }
}

# Output the unique ID of the created CTE GuardPoint
output "guardpoint_id" {
    value = ciphertrust_cte_guardpoint.dir_auto_gp.id
}