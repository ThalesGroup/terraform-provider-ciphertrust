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

resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time1.google.com"
}

output "ntp_server_host" {
	value = ciphertrust_ntp.ntp_server_1.host
}