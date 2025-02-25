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

resource "ciphertrust_syslog" "syslog_1" {
    host = "example.syslog.com"
    transport = "udp"
}

output "syslog_connection_value" {
	value = ciphertrust_syslog.syslog_1.host
}