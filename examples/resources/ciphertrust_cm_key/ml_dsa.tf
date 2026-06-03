# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a post-quantum signing key
# using the Module-Lattice Digital Signature Algorithm (ML-DSA).

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
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

# Add a CM Key that uses the post-quantum ML-DSA signature algorithm
resource "ciphertrust_cm_key" "ml_dsa_key" {
  # Name of the key
  name = "terraform-ml-dsa"

  # Cryptographic algorithm this key is used with.
  # 'ml-dsa' creates a post-quantum signing key.
  algorithm = "ml-dsa"

  # Cryptographic usage mask. Sign (1), Verify (2).
  usage_mask = 3
}

# Output the unique ID of the created CM Key
output "ml_dsa_key_id" {
  value = ciphertrust_cm_key.ml_dsa_key.id
}
