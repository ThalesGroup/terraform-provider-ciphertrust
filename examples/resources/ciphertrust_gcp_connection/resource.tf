resource "ciphertrust_gcp_connection" "connection" {
  key_file    = "gcp-key-file.json"
  name        = "gcp_connection_name"
}
