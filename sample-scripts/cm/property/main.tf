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

resource "ciphertrust_property" "property_1" {
    name = "ENABLE_RECORDS_DB_STORE"
    value = "false"
}

output "cm_property_name" {
	value = ciphertrust_property.property_1.name
}