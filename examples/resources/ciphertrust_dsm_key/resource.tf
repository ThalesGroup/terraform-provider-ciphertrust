# Indirectly this resource is dependent on a ciphertrust_dsm_connection resource
resource "ciphertrust_dsm_connection" "dsm_connection" {
  name        = "connection-name"
  nodes {
    hostname    = "host-ip-address"
    certificate = "dsm-server.pem"
  }
  password = "dsm-password"
  username = "dsm-username"
}

# This resource is dependent on a ciphertrust_dsm_domain resource
resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.dsm_connection.id
  domain_id      = dsm_domain_id
}

# Create an AES 256 bit key
resource "ciphertrust_dsm_key" "dsm_key" {
  name            = "key-name"
  algorithm       = "AES256"
  domain          = ciphertrust_dsm_domain.dsm_domain.id
  extractable     = true
  object_type     = "symmetric"
}

# Create an RSA 4069  bit key
resource "ciphertrust_dsm_key" "dsm_key" {
  name            = "key-name"
  algorithm       = "RSA4096"
  domain          = ciphertrust_dsm_domain.dsm_domain.id
  extractable     = true
  object_type     = "symmetric"
}
