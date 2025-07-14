data "ciphertrust_oci_key_list" "ciphertrust_keys" {
  # Required parameters
  key_id = "ciphertrust.oci_key.some_key.id"
  # Optional parameters
  filters = {
    limit = "-1"
  }
}
