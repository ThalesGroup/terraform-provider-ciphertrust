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

resource "ciphertrust_cte_signature_set" "signature_set" {
    name = "signature_set_tf"
    description = "SignaturSet Terraform"
    source_list = [
      "/opt/temp1",
      "/opt/temp2"
    ] 
    type = "Application"
}
