terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

data "ciphertrust_cm_groups_list" "groups_list" {
  filters = {
    name = "Key Users"
  }
  # Similarly can provide 'users', 'connection', 'clients', 'skip', 'limit'
  # to further narrow down the existing CipherTrust Manager groups.
}

output "cm_groups" {
  value = data.ciphertrust_cm_groups_list.groups_list
}
