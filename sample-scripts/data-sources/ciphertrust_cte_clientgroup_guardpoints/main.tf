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

data "ciphertrust_cte_clientgroup_guardpoint" "example" {
  clientgroup_name = ""
}


output "clientgroup_guardpoint" {
  value = "${data.ciphertrust_cte_clientgroup_guardpoint.example.clientgroup_guardpoint}"
}
