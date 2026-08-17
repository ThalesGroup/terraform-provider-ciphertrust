# Sort OCI keys by creation date, newest first.
data "ciphertrust_oci_key_list" "sorted" {
  filters = {
    sort = "-createdAt"
  }
}

# List active AES keys in a specific vault, returning all matches.
data "ciphertrust_oci_key_list" "active_aes_in_vault" {
  filters = {
    vault_name      = "prod-vault"
    algorithm       = "AES"
    lifecycle_state = "ENABLED"
    limit           = "-1"
  }
}
