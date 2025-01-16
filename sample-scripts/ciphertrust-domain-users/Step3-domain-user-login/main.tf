terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
    }
  }
}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  key_name = "UsersKey-${lower(random_id.random.hex)}"
}

# testdomainuser will be authenticated to and logged in to testdomain.
provider "ciphertrust" {
  username    = "testdomainuser"
  auth_domain = "testdomain"
  domain      = "testdomain"
}

# Being a member of the Key Users group the user can create Ciphertrust keys.
resource "ciphertrust_cm_key" "user_key" {
  name      = local.key_name
  algorithm = "AES"
}
output "user_key" {
  value = ciphertrust_cm_key.user_key
}
