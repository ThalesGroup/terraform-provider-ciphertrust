# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about the CTE client group DP Set.

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

# Data source for retrieving CTE DP set in client group details
data "ciphertrust_cte_client_group_dp_set" "example" {
  # The name filter to specify for which CTE Group Designated Primary Set to retrieve (replace with actual client group name)
 client_group_name = ""
}

output "client_group_dp_set" {
  # Output the list of DP set of a client group retrieved from the data source
  value = "${data.ciphertrust_cte_client_group_dp_set.example.client_group_dp_set}"
}
