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

data "ciphertrust_ldt_comm_group_svc_list" "example" {
  #group_name = ""
}


output "ldt_comm_groups" {
  value = "${data.ciphertrust_ldt_comm_group_svc_list.example.ldt_comm_groups}"
}
