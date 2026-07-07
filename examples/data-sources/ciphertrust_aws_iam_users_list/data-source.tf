# List all IAM users for a CipherTrust Manager AWS KMS
data "ciphertrust_aws_iam_users_list" "all" {
  kms_id = ciphertrust_aws_kms.kms.id
}

# List the first 25 IAM users whose path starts with /engineering/
data "ciphertrust_aws_iam_users_list" "engineering" {
  kms_id      = ciphertrust_aws_kms.kms.id
  max_items   = 25
  path_prefix = "/engineering/"
}
