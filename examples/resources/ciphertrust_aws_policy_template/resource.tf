resource "ciphertrust_aws_policy_template" "policy_template" {
  key_admins = ["key_administrator"]
  key_users  = ["key_user_1", "key_user_2"]
  km         = kms.id
}

