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

# Create an ML-DSA key (post-quantum signature algorithm)
resource "ciphertrust_cm_key" "ml_dsa_key" {
  name      = "ml-dsa-key"
  algorithm = "ml-dsa"
}
