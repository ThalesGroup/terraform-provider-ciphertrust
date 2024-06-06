# Get key details and versions using the CipherTrust key resource ID
data "ciphertrust_oci_external_key" "by_key_id" {
  cckm_key_id = "key ID"
}

# Get key details and versions using the key name
data "ciphertrust_oci_external_key" "by_name" {
  name = "key name"
}

# Get key details and versions using the key name and vault name
data "ciphertrust_oci_external_key" "key_by_name_and_vault_name" {
  name            = "key name"
  cckm_vault_name = "vault name"
}
