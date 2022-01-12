resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.connection.name
  name           = "short_or_long_keyring_name"
  project_id     = "project_name"
}
