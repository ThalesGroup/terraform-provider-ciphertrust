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

  resource "ciphertrust_trial_license" "trial_license" {
  }

  output "trial_license_info" {
	value = ciphertrust_trial_license.trial_license.id
  }