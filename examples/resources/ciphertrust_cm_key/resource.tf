# Create a 2048 bit RSA key
resource "ciphertrust_cm_key" "cm_rsa_key" {
  name      = "key-name"
  algorithm = "RSA"
  key_size  = 2048
}

# Create a 256 bit AES key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name      = "key-name"
  algorithm = "AES"
}

# Create a 128 bit AES key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name      = "key-name"
  algorithm = "AES"
  key_size  = 128
}

# Create a secp384r1 EC key
resource "ciphertrust_cm_key" "cm_ec_key" {
  name      = "key-name"
  algorithm = "EC"
}

# Create a curve25519 EC key
resource "ciphertrust_cm_key" "cm_ec_key" {
  name      = "key-name"
  algorithm = "EC"
  curve  = "curve25519"
}

# Create a 2048 bit HYOK RSA key
# To allow it to be destroyed including deleting in CipherTrust Manager 'undeletable' must be udpated to 'false'.
# To allow it to be destroyed but not deleted from CipherTrust Manager update 'remove_from_state_on_destroy' to 'true'.
resource "ciphertrust_cm_key" "cm_rsa_key" {
  name         = "key-name"
  algorithm    = "RSA"
  key_size     = 2048
  undeletable  = true
  unexportable = true
}

# Create a 2048 bit HYOK RSA key and allow it to be removed from terraform state on destroy but retained in CipherTrust Manager.
resource "ciphertrust_cm_key" "cm_rsa_key" {
  name         = "key-name"
  algorithm    = "RSA"
  key_size     = 2048
  undeletable  = true
  unexportable = true
  remove_from_state_on_destroy = true
}
