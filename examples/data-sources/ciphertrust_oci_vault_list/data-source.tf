# Sort OCI vaults by display name.
data "ciphertrust_oci_vault_list" "sorted" {
  filters = {
    sort = "display_name"
  }
}

# List virtual private vaults in a specific region.
data "ciphertrust_oci_vault_list" "vpv_in_region" {
  filters = {
    region     = "us-ashburn-1"
    vault_type = "VIRTUAL_PRIVATE"
  }
}
