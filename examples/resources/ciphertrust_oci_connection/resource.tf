# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of an OCI connection resource
# with the CipherTrust provider

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust Manager resources
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
  # The address of the CipherTrust Manager appliance (replace with the actual address)
  address = "https://10.10.10.10"

  # Username for authenticating with the CipherTrust Manager appliance
  username = "admin"

  # Password for authenticating with the CipherTrust Manager appliance
  password = "ChangeMe101!"
}

# Define an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = "path-to-or-contents-of-oci-key-file"
  name                = "connection-name"
  pub_key_fingerprint = "public-key-fingerprint"
  region              = "oci-region"
  tenancy_ocid        = "tenancy-ocid"
  user_ocid           = "user-ocid"
}
