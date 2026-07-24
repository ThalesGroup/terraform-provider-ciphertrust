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

data "ciphertrust_azure_connection_list" "example_azure_connection" {
   filters = {
     labels = "key=value"
   }
}

output "azure_connection_details" {
  value = data.ciphertrust_azure_connection_list.example_azure_connection
}