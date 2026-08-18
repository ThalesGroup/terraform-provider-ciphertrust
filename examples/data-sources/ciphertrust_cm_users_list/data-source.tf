# Terraform Configuration for CipherTrust Provider

# The provider is configured to connect to the CipherTrust appliance and fetch details
# about existing users.

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

# Data source for retrieving user details
data "ciphertrust_cm_users_list" "example_users" {
  # Filters to narrow down the users
  filters = {
    # The username of the user to fetch
    username = "admin"
  }
  # Similarly can provide 'name', 'email', 'groups', 'is_admin' etc to fetch existing users
  # example for fetching users belonging to a group
  # filters = {
  #   groups = "my-group"
  # }
}

# Output the details of the users. Marked sensitive because the nested
# 'password' attribute in each user object is a sensitive field.
output "users_details" {
  value     = data.ciphertrust_cm_users_list.example_users
  sensitive = true
}
