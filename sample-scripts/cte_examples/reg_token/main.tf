terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.9-beta"
    }

  }
}

provider "ciphertrust" {}

# Create a Registration Token
resource "ciphertrust_cte_registration_token" "reg_token" {
  name_prefix = "Terraform_Demo_Token"
  lifetime    = "10h"
  max_clients = 100
}


# To be used for client registration process
output "token" {
  value = ciphertrust_cte_registration_token.reg_token.token
}