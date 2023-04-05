terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.9.0-beta9"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  user_name       = "user-${lower(random_id.random.hex)}"
}

# Create a GCP connection
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = var.gcp_key_file
  name     = local.connection_name
}

# Add a GCP key ring
resource "ciphertrust_gcp_keyring" "keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.id
  name           = var.keyring
  project_id     = var.gcp_project
}

# Create a user
resource "ciphertrust_user" "user" {
  username = local.user_name
  password = "Test0123#"
}

# Add the user to the CCKM Users group
resource "ciphertrust_groups" "cckm_users" {
  name = "CCKM Users"
  user_ids = [
    ciphertrust_user.user.id,
  ]
}

# Add ACLs for the user
resource "ciphertrust_gcp_acl" "user_acls" {
  keyring_id = ciphertrust_gcp_keyring.keyring.id
  user_id    = ciphertrust_user.user.id
  actions    = ["keycreate", "keydestroy", "view"]
}
output "user_acls" {
  value = ciphertrust_gcp_acl.user_acls
}
