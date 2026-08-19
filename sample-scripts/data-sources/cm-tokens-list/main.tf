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

data "ciphertrust_cm_tokens_list" "tokens_list" {
  filters = {
    labels = "environment=devenv"
  }
  # Similarly can provide 'id', 'token', 'label' to further narrow down
  # the existing CipherTrust Manager registration tokens.
}

# The list includes each token's secret value, so the output must be marked
# sensitive.
output "cm_tokens" {
  value     = data.ciphertrust_cm_tokens_list.tokens_list
  sensitive = true
}
