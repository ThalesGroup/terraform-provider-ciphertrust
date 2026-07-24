# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MIT

terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
  address = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

data "ciphertrust_cte_ldtcommgroup_clients_list" "example" {
 group_name = ""
}


output "clients" {
   value = "${data.ciphertrust_cte_ldtcommgroup_clients_list.example.clients}"
}
