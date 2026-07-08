# List all IAM roles for a CipherTrust Manager AWS KMS
data "ciphertrust_aws_iam_roles_list" "all" {
  kms_id = ciphertrust_aws_kms.kms.id
}

# List the first 25 IAM roles whose path starts with /service-roles/
data "ciphertrust_aws_iam_roles_list" "service_roles" {
  kms_id      = ciphertrust_aws_kms.kms.id
  max_items   = 25
  path_prefix = "/service-roles/"
}
