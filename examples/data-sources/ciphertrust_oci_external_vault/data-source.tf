# Get vault details using the CipherTrust key resource ID
data "ciphertrust_oci_external_vault" "by_id" {
  cckm_vault_id = "vault ID"
}

# Get vault details and versions using the vault name
data "ciphertrust_oci_external_vault" "by_name" {
  cckm_vault_name = "vault name"
}
