# List rotation history for a specific AWS key
data "ciphertrust_aws_key_rotation_list" "rotation_list" {
  key_id = "77b4acd3-80e4-4270-81b5-11bb13b8053a"
}

# List rotation history with filters
data "ciphertrust_aws_key_rotation_list" "rotation_list_filtered" {
  key_id = "77b4acd3-80e4-4270-81b5-11bb13b8053a"
  filters = {
    limit = "-1"
  }
}
