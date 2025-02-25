terraform {
	required_providers {
	  ciphertrust = {
		source = "thalesgroup.com/oss/ciphertrust"
		version = "1.0.0"
	  }
	}
}

provider "ciphertrust" {
	address = "https://192.168.2.158"
	username = "admin"
	password = "ChangeIt01!"
	bootstrap = "no"
}

data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "%2FC%3DUS%2FST%3DTX%2FL%3DAustin%2FO%3DThales%2FCN%3DCipherTrust%20Root%20CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}

output "reg_token_value" {
	value = ciphertrust_cm_reg_token.reg_token.token
}