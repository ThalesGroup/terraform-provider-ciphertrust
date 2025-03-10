terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.9-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "google-connection-${lower(random_id.random.hex)}"
  key_name        = "google-keyring-datasource-${lower(random_id.random.hex)}"
  user_name       = "google-keyring-datasource-user-${lower(random_id.random.hex)}"
  user_password   = "password"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "connection" {
  description = "Description of the Google Cloud connection"
  key_file    = var.gcp_key_file
  meta        = { key = "value" }
  name        = local.connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "gcp_keyring" {
  gcp_connection = ciphertrust_gcp_connection.connection.name
  name           = var.keyring
  project_id     = var.gcp_project
}

# Create a CipherTrust user
resource "ciphertrust_user" "gcp_user" {
  username = local.user_name
  password = local.user_password
}

# Add some ACLs for that user
resource "ciphertrust_gcp_acl" "gcp_user_acls" {
  keyring_id = ciphertrust_gcp_keyring.gcp_keyring.id
  user_id    = ciphertrust_user.gcp_user.id
  actions    = ["view", "keycreate", "keyupload", "keyupdate", "keydestroy", "keysynchronize", "keycanceldestroy"]
}

# Get the GCP keyring data using the keyring name
data "ciphertrust_gcp_keyring" "gcp_keyring_data" {
  name = ciphertrust_gcp_keyring.gcp_keyring.name
  depends_on = [
    ciphertrust_gcp_acl.gcp_user_acls
  ]
}
output "gcp_keyring_data_using_keyring_name" {
  value = data.ciphertrust_gcp_keyring.gcp_keyring_data
}
