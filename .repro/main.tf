terraform {
  required_providers {
    ciphertrust = {
      source  = "thalesgroup.com/oss/ciphertrust"
      version = "0.0.1"
    }
  }
}

provider "ciphertrust" {
  address     = "https://ec2-44-205-177-172.compute-1.amazonaws.com"
  username    = "admin"
  password    = "Koala2.20"
  bootstrap   = "no"
  domain      = "root"
  auth_domain = "root"
}

resource "ciphertrust_cm_key" "repro" {
  name               = "tfrepro-tfin-286-549d02-1"
  algorithm          = "AES"
  key_size           = 256
  revocation_reason  = "KeyCompromise"
  revocation_message = "test-repro-message-TFIN-286"
}
