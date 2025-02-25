terraform {
	required_providers {
	  ciphertrust = {
		source = "thalesgroup.com/oss/ciphertrust"
		version = "1.0.0"
	  }
	}
}
provider "ciphertrust" {
	address = "https://192.168.2.137"
	username = "admin"
	password = "ChangeIt01!"
	bootstrap = "no"
}

resource "ciphertrust_cm_user" "testUser" {
  name="frank"
  email="frank@local"
  username="frank"
  password="ChangeIt01!"
}

output "cm_user_id" {
	value = ciphertrust_cm_user.testUser.id
}