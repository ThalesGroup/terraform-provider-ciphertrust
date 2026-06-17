# List all AWS keys (up to default limit of 10)
data "ciphertrust_aws_keys_list" "all_keys" {}

# List AWS keys filtered by region
data "ciphertrust_aws_keys_list" "keys_by_region" {
  filters = {
    region = "ap-south-2"
  }
}

# List AWS keys filtered by alias
data "ciphertrust_aws_keys_list" "keys_by_alias" {
  filters = {
    alias = "my-key"
  }
}

# List all AWS keys (no limit)
data "ciphertrust_aws_keys_list" "all_keys_no_limit" {
  filters = {
    limit = "-1"
  }
}
