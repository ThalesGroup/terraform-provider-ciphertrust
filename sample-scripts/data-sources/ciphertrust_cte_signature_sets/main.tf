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

data "ciphertrust_cte_signature_sets" "example" {
}

output "signature_sets" {
  value = "${data.ciphertrust_cte_signature_sets.example.signature_sets}"
}
