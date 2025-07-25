terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.11.2"
    }
  }
}

provider "ciphertrust" {}

resource "ciphertrust_cte_ldtgroupcomms" "lgs" {
  name        = "test_lgs"
  description = "Testing ldt comm group using Terraform"
  client_list = "client1,client2"
}