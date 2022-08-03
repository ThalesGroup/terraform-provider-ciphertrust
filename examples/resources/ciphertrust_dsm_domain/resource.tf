# This resource is dependent on a ciphertrust_dsm_connection resource
resource "ciphertrust_dsm_connection" "dsm_connection" {
  name        = "connection-name"
  nodes {
    hostname    = "host-ip-address"
    certificate = "dsm-server.pem"
  }
  password = "dsm_password"
  username = "dsm_username"
}

# Assign a DSM domain to the connection
resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.dsm_connection.id
  domain_id      = dsm_domain_id
}

# Create a DSM key
resource "ciphertrust_dsm_key" "dsm_key" {
  name            = "key-name"
  algorithm       = "RSA2048"
  domain          = ciphertrust_dsm_domain.dsm_domain.id
  extractable     = true
  object_type     = "asymmetric"
}
