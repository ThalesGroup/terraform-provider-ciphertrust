terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.6-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "gcp-connection-${lower(random_id.random.hex)}"
  group_user_name = "group-user-${lower(random_id.random.hex)}"
  group_name      = "group-${lower(random_id.random.hex)}"
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
resource "ciphertrust_user" "group_user" {
  username = local.group_user_name
  password = "Test0123#"
}

# Add the user to the CCKM Users group
resource "ciphertrust_groups" "cckm_users" {
  name = "CCKM Users"
  user_ids = [
    ciphertrust_user.group_user.id,
  ]
}

# Create a group and add the user
resource "ciphertrust_groups" "group" {
  name     = local.group_name
  user_ids = [ciphertrust_user.group_user.id]
}

# Add an acl for the group
resource "ciphertrust_gcp_acl" "group_acls" {
  keyring_id = ciphertrust_gcp_keyring.keyring.id
  group      = ciphertrust_groups.group.id
  actions    = ["view", "keycreate", "keyupload", "keyupdate", "keydestroy"]
}
output "group_acls" {
  value = ciphertrust_gcp_acl.group_acls
}
