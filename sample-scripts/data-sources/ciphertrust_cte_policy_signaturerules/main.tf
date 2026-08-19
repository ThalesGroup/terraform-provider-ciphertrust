terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/CipherTrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {
  address = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

data "ciphertrust_cte_policy_signature_rules" "example" {
  policy = ""
}

output "rules" {
  value = "${data.ciphertrust_cte_policy_signature_rules.example.rules}"
}
