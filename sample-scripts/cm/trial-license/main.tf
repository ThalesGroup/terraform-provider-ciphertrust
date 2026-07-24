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

  resource "ciphertrust_trial_license" "trial_license" {
  }

  output "trial_license_info" {
	value = ciphertrust_trial_license.trial_license.id
  }