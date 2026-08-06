# Sort XKS keys by creation date, newest first.
data "ciphertrust_aws_xks_keys_list" "sorted" {
  filters = {
    sort = "-createdAt"
  }
}

# List XKS keys by region and alias.
data "ciphertrust_aws_xks_keys_list" "by_region_and_alias" {
  filters = {
    region = "us-east-1"
    alias  = "my-xks-key"
  }
}
