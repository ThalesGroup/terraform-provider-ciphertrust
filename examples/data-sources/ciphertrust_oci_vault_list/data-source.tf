data "ciphertrust_oci_vault_list" "ciphertrust_vaults" {
  # Optional parameters
  filters = {
    name = "vault-name"
  }
}
