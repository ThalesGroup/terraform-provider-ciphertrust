# Sort KMS resources by last updated, newest first.
data "ciphertrust_aws_kms_list" "sorted" {
  filters = {
    sort = "-updatedAt"
  }
}

# List KMS resources for a specific account and cloud partition.
data "ciphertrust_aws_kms_list" "by_account_and_cloud" {
  filters = {
    account_id = "123456789012"
    cloud_name = "aws"
  }
}
