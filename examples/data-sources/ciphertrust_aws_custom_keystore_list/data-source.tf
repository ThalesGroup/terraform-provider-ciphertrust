# List all custom key stores (up to default limit of 10)
data "ciphertrust_aws_custom_keystore_list" "all" {}

# List custom key stores filtered by name
data "ciphertrust_aws_custom_keystore_list" "by_name" {
  filters = {
    name = "my-keystore"
  }
}

# List all custom key stores (no limit)
data "ciphertrust_aws_custom_keystore_list" "all_no_limit" {
  filters = {
    limit = "-1"
  }
}
