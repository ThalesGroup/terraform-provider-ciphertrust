# Sort CloudHSM keys by creation date, newest first.
data "ciphertrust_aws_cloudhsm_keys_list" "sorted" {
  filters = {
    sort = "-createdAt"
  }
}

# List enabled CloudHSM keys in a specific region.
data "ciphertrust_aws_cloudhsm_keys_list" "enabled_in_region" {
  filters = {
    region  = "us-east-1"
    enabled = "true"
  }
}
