terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

data "ciphertrust_cm_keys_list" "keys_list" {
  filters = {
    algorithm = "aes"
  }
  # Similarly can provide 'name', 'id', 'uuid', 'state', 'labels', 'skip', 'limit'
  # etc to further narrow down the existing CipherTrust Manager keys.
}

output "cm_keys" {
  value = data.ciphertrust_cm_keys_list.keys_list
}
