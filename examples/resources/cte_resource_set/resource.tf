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

# Add a resource of type CTE Resource Set with the name resource_set
resource "ciphertrust_cte_resource_set" "resource_set" {
    name = "resource_set_tf"
    description = "ResourceSet Terraform"
    labels = {
      key1 = "value1"
      key2 = "value2"
    }
    resources = [
      {
        directory = "/opt/temp1"
        file = "*"
        include_subfolders = true
        hdfs = false
      }
    ]
}

# Output the unique ID of the created CTE Resource Set
output "resource_set_id" {
    # The value will be the ID of the CTE Resource Set resource
    value = ciphertrust_cte_resource_set.resource_set.id
}

# Output the name of the created CTE Resource Set
output "resource_set_name" {
    # The value will be the name of the CTE Resource Set resource
    value = ciphertrust_cte_resource_set.resource_set.name
}