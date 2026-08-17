# Sort keys by creation date, newest first.
data "ciphertrust_aws_keys_list" "sorted" {
  filters = {
    sort = "-createdAt"
  }
}

# List enabled keys in a specific region, returning all matches.
data "ciphertrust_aws_keys_list" "enabled_in_region" {
  filters = {
    region  = "us-east-1"
    enabled = "true"
    limit   = "-1"
  }
}
