terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.4-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  aes_name               = "cm-aes-${lower(random_id.random.hex)}"
  ec_name                = "cm-ec-${lower(random_id.random.hex)}"
  rsa_name               = "cm-rsa-${lower(random_id.random.hex)}"
  hyok_name              = "cm-hyok-${lower(random_id.random.hex)}"
}

# Create a 256 bit CipherTrust AES key
resource "ciphertrust_cm_key" "cm_aes" {
  name      = local.aes_name
  algorithm = "AES"

}
output "cm_aes" {
  value = ciphertrust_cm_key.cm_aes
}

# Create a 4096 bit CipherTrust RSA key
resource "ciphertrust_cm_key" "cm_rsa" {
  name      = local.rsa_name
  algorithm = "RSA"
  key_size  = 4096
}
output "cm_rsa" {
  value = ciphertrust_cm_key.cm_rsa
}

# Create a secp256k1 CipherTrust EC key
resource "ciphertrust_cm_key" "cm_ec" {
  name      = local.ec_name
  algorithm = "EC"
  curve     = "secp256k1"

}
output "cm_ec" {
  value = ciphertrust_cm_key.cm_ec
}

# Create a key that can be used for Hold Your Own Key (HYOK) keys, eg: AWS XKS key, OCI External key
# Note this key can not be destroyed until undeleteable is set as false and the key is updated
resource "ciphertrust_cm_key" "cm_hyok" {
  name         = local.hyok_name
  algorithm    = "AES"
  unexportable = true
  undeletable  = true
}
output "cm_hyok" {
  value = ciphertrust_cm_key.cm_hyok
}
