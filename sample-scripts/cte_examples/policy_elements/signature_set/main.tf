terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.9-beta"
    }
  }
}

provider "ciphertrust" {}

#Creating a signature set
resource "ciphertrust_cte_sig_set" "sig_set" {
  name        = "SigSet"
  description = "Test Sig set"
  type        = "Application"
  source_list = ["/root/tmps", "/usr/bin/", "/root/test"]
}