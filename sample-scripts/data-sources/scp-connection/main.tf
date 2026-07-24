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

data "ciphertrust_scp_connection_list" "example_scp_connection" {
  filters = {
    labels = "s=S"
  }
}

output "scp_connection_details" {
  value = data.ciphertrust_scp_connection_list.example_scp_connection
}
