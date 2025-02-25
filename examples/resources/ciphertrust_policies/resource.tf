# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a policy resource
# with the CipherTrust provider, including setting up policy details.

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

# Add a resource of type CM policy with the name my_policy
resource "ciphertrust_policies" "policy" {
  	# Name of the policy
    name    =   "my_policy"

    # Action attribute of an operation is a string, in the form of VerbResource e.g. CreateKey, or VerbWithResource e.g. EncryptWithKey
    actions =   ["ReadKey"]

    # Allow is the effect of the policy, either to allow the actions or to deny the actions.
    allow   =   true

    # Specifies the effect of the policy, either to allow or to deny.
    effect  =   "allow"

    # Conditions are rules for matching the other attributes of the operation
    conditions = [{
        path   = "context.resource.alg"
        op     = "equals"
        values = ["aes","rsa"]
    }]
}

# Output the unique ID of the created CM policy
output "cm_policy_id" {
	value = ciphertrust_policies.policy.id
}