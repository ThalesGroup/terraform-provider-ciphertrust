# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a registry token resource
# with the CipherTrust provider, including setting up registration  details.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
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
  # The address of the CipherTrust appliance (replace with the actual address)
  address = "https://10.10.10.10"

  # Username for authenticating with the CipherTrust appliance
  username = "admin"

  # Password for authenticating with the CipherTrust appliance
  password = "ChangeMe101!"
}

# Fetch the CA ID for the default CA "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    # The provider URL-encodes filter values itself before sending them to
    # CipherTrust Manager, so this must be the raw subject string, not a
    # pre-encoded one (a pre-encoded value here would be double-encoded).
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

# Add a resource of type CM Registration Token with the CA ID
resource "ciphertrust_cm_reg_token" "reg_token" {
  # Use the above CA ID for creating registration token
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}

# Output the created registration token. Marked sensitive because 'token' is
# a sensitive field.
output "reg_token_value" {
  value     = ciphertrust_cm_reg_token.reg_token.token
  sensitive = true
}