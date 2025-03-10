# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a trial license activation resource
# with the CipherTrust provider.

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

# Add a resource of type CM trial license activation
resource "ciphertrust_trial_license" "trial_license" {

}

# Output the unique ID of the created trial license
output "trial_license_info" {
	value = ciphertrust_trial_license.trial_license.id
}