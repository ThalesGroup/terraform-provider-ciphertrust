# This resource is dependent on a ciphertrust_gcp_connection resource
resource "ciphertrust_gcp_connection" "gcp_connection" {
  key_file = "gcp-key-file.json"
  name     = "connection-name"
}

# Create a keyring resource and assign it to the connection
resource "ciphertrust_gcp_keyring" "gcp_keyring" {
  gcp_connection = ciphertrust_gcp_connection.gcp_connection.name
  name           = "keyring-name"
  project_id     = "project-id"
}

# Create a user
resource "ciphertrust_user" "user" {
  username = "username"
  password = "password"
}

# Create another user which will be added to a group
resource "ciphertrust_user" "group_user" {
  username = "group_user"
  password = "password"
}

# Create a group and add the user
resource "ciphertrust_groups" "group" {
  name     = "group"
  user_ids = [ciphertrust_user.group_user.id]
}

# Users must be a member of the CCKM Users group to perform operations on cloud keys
resource "ciphertrust_groups" "cckm_users" {
  name = "CCKM Users"
  user_ids = [
    ciphertrust_user.user.id,
    ciphertrust_user.group_user.id,
  ]
}

# Users must be a member of the Key Users group to perform operations on CipherTrust keys
# For example, create a CipherTrust key to upload it to a cloud
resource "ciphertrust_groups" "key_users" {
  name = "Key Users"
  user_ids = [
    ciphertrust_user.group_user.id,
  ]
}

# Add an acl for the user to the keyring
resource "ciphertrust_gcp_acl" "user_acls" {
  keyring_id = ciphertrust_gcp_keyring.gcp_keyring.id
  user_id    = ciphertrust_user.user.id
  actions    = ["keycreate", "keyupload", "view"]
}

# Add an acl for the group to the keyring
resource "ciphertrust_gcp_acl" "test_group_acls" {
  keyring_id = ciphertrust_gcp_keyring.gcp_keyring.id
  group      = ciphertrust_groups.group.id
  actions    = ["view", "keyupload", "keydestroy"]
}
