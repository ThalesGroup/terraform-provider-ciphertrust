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

data "ciphertrust_cte_clients_list" "data_client_list1" {
  filters = {
    name = "sjavlr89-sah-s3-test-cteu.sjcicd.com"
  }
}

output "cte_list" {
  value = "${data.ciphertrust_cte_clients_list.data_client_list1.clients}"
}
