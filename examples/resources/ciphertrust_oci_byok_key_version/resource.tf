resource "ciphertrust_cm_key" "cm_key_version" {
  name       = "test-key-name"
  algorithm  = "AES"
  usage_mask = 60
}

# Add a BYOK key version to a native OCI key
resource "ciphertrust_oci_byok_key_version" "byok_version_0" {
  # Required parameters
  cckm_key_id                = ciphertrust_oci_key.test_key.id
  source_key_id              = ciphertrust_cm_key.cm_key_version.id
  # Optional parameters
  schedule_for_deletion_days = 14
  source_key_tier            = "local"
}

# Add a BYOK key version to a BYOK OCI key
resource "ciphertrust_oci_byok_key_version" "byok_version_0" {
  cckm_key_id     = ciphertrust_oci_byok_key.test_key.id
  source_key_id   = ciphertrust_cm_key.cm_key_version.id
  source_key_tier = "local"
}
