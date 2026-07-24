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

resource "ciphertrust_syslog" "syslog_1" {
    host = "example.syslog.com"
    transport = "udp"
}

output "syslog_connection_value" {
	value = ciphertrust_syslog.syslog_1.host
}