# List all AWS CloudHSM keys (up to default limit of 10)
data "ciphertrust_aws_cloudhsm_keys_list" "all_keys" {}

# List AWS CloudHSM keys filtered by region
data "ciphertrust_aws_cloudhsm_keys_list" "keys_by_region" {
  filters = {
    region = "ap-south-2"
  }
}

# List all AWS CloudHSM keys (no limit)
data "ciphertrust_aws_cloudhsm_keys_list" "all_keys_no_limit" {
  filters = {
    limit = "-1"
  }
}
