# List all AWS XKS keys (up to default limit of 10)
data "ciphertrust_aws_xks_keys_list" "all_keys" {}

# List AWS XKS keys filtered by region
data "ciphertrust_aws_xks_keys_list" "keys_by_region" {
  filters = {
    region = "ap-south-2"
  }
}

# List all AWS XKS keys (no limit)
data "ciphertrust_aws_xks_keys_list" "all_keys_no_limit" {
  filters = {
    limit = "-1"
  }
}
