terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.2-beta"
    }
  }
}

# Authenticate as an administrator and log into the root domain.
provider "ciphertrust" {
  username = "admin-user"
}

# Create a domain, adding admin-user as an administrator of the domain
resource "ciphertrust_domain" "cm_domain" {
  name                  = "testdomain"
  admins                = ["admin-user"]
  allow_user_management = true
}
