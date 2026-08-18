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
      version = "1.0.1"
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

# Define an OCI connection. CipherTrust Manager validates 'region' and the
# 'ocid1.<type>.<realm>..<unique-id>' shape of the OCID fields, even when the
# credentials themselves are not real. Set skip_connection_params_test to
# true to bypass the live credential connectivity test against OCI itself.
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file                    = "path-to-or-contents-of-oci-key-file"
  name                        = "connection-name"
  pub_key_fingerprint         = "public-key-fingerprint"
  region                      = "us-ashburn-1"
  tenancy_ocid                = "ocid1.tenancy.oc1..aaaaaaaaexampletenancyocid"
  user_ocid                   = "ocid1.user.oc1..aaaaaaaaexampleuserocid"
  skip_connection_params_test = true
}
