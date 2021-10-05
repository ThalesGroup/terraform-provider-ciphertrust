resource "ciphertrust_cm_key" "cm_key" {
  name      = "key_name"
  algorithm = "RSA"
  key_size  = 4096
}

