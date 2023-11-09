# Create a 2048 bit RSA key
resource "ciphertrust_cm_key" "cm_rsa_key" {
  name      = "key-name"
  algorithm = "RSA"
  key_size  = 2048
}

# Create a secp384r1 EC key
resource "ciphertrust_cm_key" "cm_ec_key" {
  name      = "key-name"
  algorithm = "EC"
}

# Create a 256 bit AES key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name      = "key-name"
  algorithm = "AES"
}

# Create a curve25519 EC key
resource "ciphertrust_cm_key" "cm_ec_key" {
  name      = "key-name"
  algorithm = "EC"
  curve  = "curve25519"
}