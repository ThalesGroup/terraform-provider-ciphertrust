resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = "10.123.45.67"
  hsm_certificate = "hsm-server.pem"
}

