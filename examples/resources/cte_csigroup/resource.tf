# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE CSIGroup resource
# with the CipherTrust provider, including setting up CTE CSIGroup details.

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

# Add a resource of type CTE CSIGroup with the name TF_CSI_Group
resource "ciphertrust_cte_csigroup" "csigroup" {
    kubernetes_namespace = "default"
    kubernetes_storage_class = "tf_class"
    name = "TF_CSI_Group"
    description = "Created via TF"
}

# Output the unique ID of the created CTE CSIGroup
output "cte_csigroup_id" {
    value = ciphertrust_cte_csigroup.csigroup.id
}