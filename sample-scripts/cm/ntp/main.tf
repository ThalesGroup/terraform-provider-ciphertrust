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

resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time1.google.com"
}

output "ntp_server_host" {
	value = ciphertrust_ntp.ntp_server_1.host
}