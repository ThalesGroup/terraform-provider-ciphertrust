# Define an ACL for a CipherTrust Manager user
resource "ciphertrust_aws_acl" "user_acl" {
  kms     = "ciphertrust-kms-id"
  user_id = "ciphertrust-user-id"
  actions = ["keycreate", "keyupdate", "keydelete"]
}

# Define an ACL for a CipherTrust Manager group
resource "ciphertrust_aws_acl" "group_acl" {
  kms     = "ciphertrust-kms-id"
  group   = "ciphertrust-group-name"
  actions = ["keycreate", "keyupdate", "keydelete"]
}
