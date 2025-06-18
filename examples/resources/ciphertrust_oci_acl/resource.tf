# Define an ACL for a CipherTrust Manager user
resource "ciphertrust_oci_acl" "user_acl" {
  vault_id = "ciphertrust-vault-id"
  user_id  = "ciphertrust-user-id"
  actions  = ["view", "keycreate", "keyupdate", "keydelete"]
}

# Define an ACL for a CipherTrust Manager group
resource "ciphertrust_oci_acl" "group_acl" {
  vault_id = "ciphertrust-vault-id"
  group    = "ciphertrust-group-name"
  actions  = ["keycreate", "keyupdate", "keydelete"]
}
