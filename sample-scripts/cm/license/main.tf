terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

resource "ciphertrust_license" "license_1" {
  license = "paste-your-CipherTrust-Manager-license-string-here"
}

output "license_id" {
  value = ciphertrust_license.license_1.id
}
