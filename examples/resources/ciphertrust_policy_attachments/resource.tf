# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CipherTrust policy attachment resource
# with the CipherTrust provider, including setting up Policy Attachment details.

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

# Add a resource of type CM policy attachment for the policy named mypolicy
resource "ciphertrust_policy_attachments" "policy_attachment" {
  # The ID for the policy to be attached.
  policy = "mypolicy"

  # Selects which principals to apply the policy to
	principal_selector = {
		acct = "pers-jsmith"
		user = "apitestuser"
	}
}

# Output the unique ID of the created CM policy attachment
output "cm_policy_attachment_id" {
	value = ciphertrust_policy_attachments.policy_attachment.id
}