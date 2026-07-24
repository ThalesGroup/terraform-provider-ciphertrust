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

data "ciphertrust_cte_policies_list" "example" {
 #policy_name == "" 
}


output "cte_policies" {
  value = "${data.ciphertrust_cte_policies_list.example.cte_policies}"
}
