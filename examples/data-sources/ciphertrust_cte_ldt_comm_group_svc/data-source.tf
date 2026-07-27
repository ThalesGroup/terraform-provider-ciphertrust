# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the CTE LDTCommGroup.

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

# Data source for retrieving LDT CommGroup  details
data "ciphertrust_ldt_comm_group_svc_list" "example" {
  #To filter for only one LDTcomm group provide its name, this is optional
  group_name = ""
}

output "ldt_comm_groups" {
  # Output the list of LDTcomm group  retrieved from the data source
  value = data.ciphertrust_ldt_comm_group_svc_list.example.ldt_comm_groups
}
