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

# Add a resource of type CTE Signature Set with the name signature_set
resource "ciphertrust_cte_signature_set" "signature_set" {
    name = "signature_set_tf"
    description = "SignaturSet Terraform"
    labels = {
      key1 = "value1"
      key2 = "value2"
    }
    source_list = [
      "/opt/temp1"
    ]
}

# Output the unique ID of the created CTE Signature Set
output "signature_set_id" {
    # The value will be the ID of the CTE Signature Set resource
    value = ciphertrust_cte_signature_set.signature_set.id
}

# Output the name of the created CTE Signature Set
output "signature_set_name" {
    # The value will be the name of the CTE Signature Set resource
    value = ciphertrust_cte_signature_set.signature_set.name
}