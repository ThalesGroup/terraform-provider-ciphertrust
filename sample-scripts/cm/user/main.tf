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

resource "ciphertrust_cm_user" "testUser" {
  name="frank"
  email="frank@local"
  username="frank"
  password="ChangeIt01!"
}

output "cm_user_id" {
	value = ciphertrust_cm_user.testUser.id
}