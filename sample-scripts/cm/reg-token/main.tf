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

data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}

output "reg_token_value" {
	value     = ciphertrust_cm_reg_token.reg_token.token
	sensitive = true
}
