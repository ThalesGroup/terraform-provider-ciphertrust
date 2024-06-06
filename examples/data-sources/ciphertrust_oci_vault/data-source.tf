# Get details of an OCI vault using vault ID
data "ciphertrust_oci_vault" "by_id" {
  cckm_vault_id = "CipherTrust vault resource ID"
}

# Get details of an OCI vault using vault name
data "ciphertrust_oci_vault" "by_name" {
  cckm_vault_name = "vault name"
}
