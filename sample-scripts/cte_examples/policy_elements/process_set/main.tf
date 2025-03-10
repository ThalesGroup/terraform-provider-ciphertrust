terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.10.8-beta"
    }
  }
}

provider "ciphertrust" {}

#Creating a process set
resource "ciphertrust_cte_process_set" "process_set" {
  name        = "process_set"
  description = "Process set test"
  processes {
    directory = "/root/tmp"
    file      = "*"
    signature = "bf2c14e0-0955-48a4-903e-e833ef8b429e"
  }
  processes {
    directory = "/root/tmp1"
    file      = "*"
    signature = "bf2c14e0-0955-48a4-903e-e833ef8b429e"
  }
}