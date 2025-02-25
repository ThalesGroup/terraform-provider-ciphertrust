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
	alias = "primary"
}

 provider "ciphertrust" {
	address = "https://192.168.2.156"
	username = "admin"
	password = "ChangeIt01!"
	bootstrap = "no"
	alias = "secondary"
}

resource "ciphertrust_trial_license" "trial_license_primary" {
	provider = ciphertrust.primary
}

output "trial_license_info_primary" {
	value = ciphertrust_trial_license.trial_license_primary.id
}

resource "ciphertrust_trial_license" "trial_license_sec" {
	provider = ciphertrust.secondary
}

output "trial_license_info_sec" {
	value = ciphertrust_trial_license.trial_license_sec.id
}

resource "ciphertrust_cluster" "cluster_info" {
	provider = ciphertrust.primary
	nodes = [
		{
			host = "https://192.168.2.158"
			port = 5432
			original = true
			public_address = "https://192.168.2.158"
			credentials = {
				username = "admin"
				password = "ChangeIt01!"
			}
		},
		{
			host = "https://192.168.2.156"
			port = 5432
			original = false
			public_address = "https://192.168.2.156"
			credentials = {
				username = "admin"
				password = "ChangeIt01!"
			}
		}
	]
}