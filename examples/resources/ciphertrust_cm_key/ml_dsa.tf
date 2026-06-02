# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an ML-DSA key
# (Module-Lattice Digital Signature Algorithm, FIPS 204) — a post-quantum
# signature algorithm — with the CipherTrust provider.

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

# Add a CM Key using the post-quantum ML-DSA signature algorithm.
resource "ciphertrust_cm_key" "ml_dsa_key" {
  # Name of the key
  name = "terraform_ml_dsa"

  # Cryptographic algorithm this key is used with.
  # 'ml-dsa' selects ML-DSA (Module-Lattice Digital Signature Algorithm, FIPS 204).
  algorithm = "ml-dsa"

  # Cryptographic usage mask. Sign (1) + Verify (2) = 3.
  usage_mask = 3

  # Key is deletable
  undeletable = false

  # Key is exportable
  unexportable = false
}

# Output the unique ID of the created CM Key
output "ml_dsa_key_id" {
  value = ciphertrust_cm_key.ml_dsa_key.id
}
