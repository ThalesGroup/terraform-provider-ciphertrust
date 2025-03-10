# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a license resource
# with the CipherTrust provider, including setting up license details.

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

# Add a resource of type CM license with a license key
resource "ciphertrust_license" "license_1" {
    license = "16 Virtual_KeySecure Ni LONG NORMAL STANDALONE AGGR 1_KEYS INFINITE_KEYS 14 JUN 2022 4 0 13 JUN 2023 4 0 NiL SLM_CODE CL_ND_LCK NiL *1CXX6B9ALEHNNK80400 NiL NiL NiL 5_MINS NiL 0 u7xXHBhSi7DPpiv0yHMdLrPjCepOPBLaXkHBIXh4Bw39lsRApgHtfEOFEiWmiE01ffliGjvlthZ995nqdRcrx0VC##AID=2d3ffc2b-6263-4d99-889f-2abab8ace4a6"
}

# Output the unique ID of the created CM license
output "license_id" {
    value = ciphertrust_license.license_1.id
}