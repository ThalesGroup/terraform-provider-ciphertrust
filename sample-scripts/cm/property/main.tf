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

resource "ciphertrust_property" "property_1" {
    name = "ENABLE_RECORDS_DB_STORE"
    value = "false"
}

output "cm_property_name" {
	value = ciphertrust_property.property_1.name
}