# List all AWS KMS resources (up to default limit of 10)
data "ciphertrust_aws_kms_list" "all_kms" {}

# List AWS KMS resources matching a name
data "ciphertrust_aws_kms_list" "kms_by_name" {
  filters = {
    name = "my-kms"
  }
}

# List all AWS KMS resources (no limit)
data "ciphertrust_aws_kms_list" "all_kms_no_limit" {
  filters = {
    limit = "-1"
  }
}
