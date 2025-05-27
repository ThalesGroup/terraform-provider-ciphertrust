# Retrieve a CipherTrust Manager vault by name
data "ciphertrust_oci_vault_list" "by_name" {
  filters = {
    name = "vault_name"
  }
}

# Retrieve all CipherTrust Manager vaults
data "ciphertrust_oci_vault_list" "all_vaults" {
}
