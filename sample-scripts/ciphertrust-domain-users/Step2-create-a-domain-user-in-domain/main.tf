terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
    }
  }
}

# admin-user will be authenticated in the root domain but logged into testdomain.
provider "ciphertrust" {
  username    = "admin-user"
  domain      = "testdomain"
}

# Create a user in the domain
resource "ciphertrust_user" "domain_user" {
  username       = "testdomainuser"
  password       = "SkyPilot.000"
  is_domain_user = true
}

# Add user to Key Users group so they can create Ciphertrust Keys
resource "ciphertrust_groups" "key_users" {
  name = "Key Users"
  user_ids = [
    ciphertrust_user.domain_user.id,
  ]
}
