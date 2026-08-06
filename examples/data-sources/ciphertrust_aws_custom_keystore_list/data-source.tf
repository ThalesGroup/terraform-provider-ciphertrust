# Sort custom key stores alphabetically by name.
data "ciphertrust_aws_custom_keystore_list" "sorted" {
  filters = {
    sort = "name"
  }
}

# List external key stores in a specific region.
data "ciphertrust_aws_custom_keystore_list" "xks_in_region" {
  filters = {
    region                = "us-east-1"
    custom_key_store_type = "EXTERNAL_KEY_STORE"
  }
}
