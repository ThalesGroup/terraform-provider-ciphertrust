# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an SCP connection resource
# with the CipherTrust provider, including setting up SCP connection details,
# labels, and custom metadata.

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

# Add a resource of type CTE User Set with the name user_set
resource "ciphertrust_cte_user_set" "user_set" {
    name = "user_set_tf"
    description = "UserSet Terraform"
    labels = {
      key1 = "value1"
      key2 = "value2"
    }
    users = [
      {
        uname = "john.doe"
      }
    ]
}

# Output the unique ID of the created CTE UserSet
output "user_set_id" {
    # The value will be the ID of the CTE UserSet resource
    value = ciphertrust_cte_user_set.user_set.id
}

# Output the name of the created CTE UserSet
output "user_set_name" {
    # The value will be the name of the CTE UserSet resource
    value = ciphertrust_cte_user_set.user_set.name
}