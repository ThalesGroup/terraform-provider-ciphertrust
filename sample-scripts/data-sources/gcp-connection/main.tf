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

data "ciphertrust_gcp_connection_list" "example_gcp_connection" {
   filters = {
     labels = "key=value"
   }
}

output "gcp_connection_details" {
  value = data.ciphertrust_gcp_connection_list.example_gcp_connection
}