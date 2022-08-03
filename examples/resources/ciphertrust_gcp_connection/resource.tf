# Create a connection to Google cloud
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = "gcp-key-file.json"
  name     = "connection-name"
}

# Assign a keyring to the connection
resource "ciphertrust_gcp_keyring" "gcp_keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.name
  name           = "keyring-name"
  project_id     = "project-id"
}

# Create a Google cloud key
resource "ciphertrust_gcp_key" "gcp_key" {
  algorithm = "RSA_DECRYPT_OAEP_4096_SHA512"
  key_ring  = ciphertrust_gcp_keyring.gcp_keyring.id
  name      = "key-name"
}

