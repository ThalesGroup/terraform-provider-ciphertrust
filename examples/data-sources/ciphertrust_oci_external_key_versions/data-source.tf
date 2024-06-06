# Get all key versions
data "ciphertrust_oci_external_key_versions" "all_versions" {
  cckm_key_id     = "CipherTrust key resource ID"
}

# Get a specific key version
data "ciphertrust_oci_external_key_versions" "specific_version" {
  cckm_key_id     = "CipherTrust key resource ID"
  cckm_version_id = "CipherTrust key version resource ID"
}
