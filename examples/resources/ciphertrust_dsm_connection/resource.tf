# Create a DSM connection
resource "ciphertrust_dsm_connection" "dsm_connection" {
  name        = "connection-name"
  nodes {
    hostname    = "host-ip-address"
    certificate = "dsm-server.pem"
  }
  password = "dsm-password"
  username = "dsm-username"
}

# Assign a DSM domain to the connection
resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.dsm_connection.id
  domain_id      = "domain-id"
}

# Create a DSM key
resource "ciphertrust_dsm_key" "dsm_key" {
  name            = "key-name"
  algorithm       = "AES256"
  domain          = ciphertrust_dsm_domain.dsm_domain.id
  extractable     = true
  object_type     = "symmetric"
}
