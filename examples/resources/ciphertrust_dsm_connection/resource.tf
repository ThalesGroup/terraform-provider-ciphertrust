resource "ciphertrust_dsm_connection" "connection" {
  name        = "dsm_connection_name"
  nodes {
    hostname    = "10.134.183.43"
    certificate = "dsm-server.pem"
  }
  password = "dsm_password"
  username = "dsm_username"
}
