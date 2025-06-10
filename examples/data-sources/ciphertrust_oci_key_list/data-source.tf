data "ciphertrust_oci_key_list" "ciphertrust_keys" {
  # Optional parameters
  filters = {
    vault_name = "vault-name"
    limit      = "-1"
  }
}
