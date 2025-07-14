# Add a native key version to a native OCI key
resource "ciphertrust_oci_byok_key_version" "byok_version_0" {
  # Required parameters
  cckm_key_id = ciphertrust_oci_key.test_key.id
  # Optional parameters
  schedule_for_deletion_days = 14
}

# Add a native key version to a BYOK OCI key
resource "ciphertrust_oci_byok_key_version" "byok_version_0" {
  cckm_key_id = ciphertrust_oci_byok_key.test_key.id
}
