resource "ciphertrust_cm_key" "test_key" {
  name       = "test-key-name"
  algorithm  = "RSA"
  usage_mask = 60
  key_size   = 2048
}

resource "ciphertrust_oci_byok_key" "test_key" {
  # Required parameters
  name          = "key-name"
  source_key_id = ciphertrust_cm_key.test_key.id
  vault         = "vault-id"
  oci_key_params = {
    compartment_id  = "compartment-ocid"
    protection_mode = "SOFTWARE"
    # Optional oci_key_params
    defined_tags = [
      {
        tag = "oci-namespace"
        values = {
          key-tag = "key-value"
        }
      }
    ]
    freeform_tags = {
      key-tag = "key-value"
    }
  }
  # Optional parameters
  source_key_tier = "local"
  enable_auto_rotation = {
    job_config_id = "ciphertrust.scheduler.scheduled.rotation_job.id"
    key_source    = "ciphertrust"
  }
  enable_key                 = true
  schedule_for_deletion_days = 14
}
