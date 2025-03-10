# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE Client Policy resource
# with the CipherTrust provider, including setting up policy details.

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

# Add a resource of type CTE Policy with the name API_Policy
resource "ciphertrust_cte_policies" "test_policy_gp" {
  name        = "API_Policy"
  type        = "Standard"
  description = "Temp policy for testing using terrafrom."
  never_deny  = true
  security_rules {
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
  }
}

# Output the unique ID of the created CTE Policy
output "policy_id" {
    value = ciphertrust_cte_policies.test_policy_gp.id
}